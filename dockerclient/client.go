package dockerclient

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/builder/dockerfile/parser"
	docker "github.com/fsouza/go-dockerclient"
	"github.com/golang/glog"

	"github.com/openshift/imagebuilder"
	"github.com/openshift/imagebuilder/imageprogress"
)

// NewClientFromEnv is exposed to simplify getting a client when vendoring this library.
func NewClientFromEnv() (*docker.Client, error) {
	return docker.NewClientFromEnv()
}

// Mount represents a binding between the current system and the destination client
type Mount struct {
	SourcePath      string
	DestinationPath string
}

type Stage struct {
	// TempDir is the temporary directory to use for storing file
	// contents. If unset, the default temporary directory for the
	// system will be used.
	TempDir string
	// Client is a client to a Docker daemon.
	Client *docker.Client
	// A compressed or uncompressed tar archive that should be used
	// as the build context.
	ContextArchive string
	// Tag is an optional value to tag the resulting built image.
	Tag string
	// Additional tags is an optional array of other tags to apply
	// to the image.
	AdditionalTags []string
	// The path within the container to perform the transient mount.
	ContainerTransientMount string
	// Container is optional and can be set to a container to use as
	// the execution environment for a build.
	Container *docker.Container
	// Command, if set, will be used as the entrypoint for the new
	// container. This is ignored if Container is set.
	Command []string
	// Image is optional and may be set to control which image is used
	// as a base for this build. Otherwise the FROM value from the
	// Dockerfile is read (will be pulled if not locally present).
	Image *docker.Image
	// HostConfig is used to start the container (if necessary).
	HostConfig *docker.HostConfig
	// Volumes handles saving and restoring volumes after RUN
	// commands are executed.
	Volumes *ContainerVolumeTracker
}

// ClientExecutor can run Docker builds from a Docker client.
type ClientExecutor struct {
	// Excludes are a list of file patterns that should be excluded
	// from the context. Will be set to the contents of the
	// .dockerignore file if nil.
	Excludes []string
	// Directory is the context directory to build from, will use
	// the current working directory if not set. Ignored if
	// ContextArchive is set.
	Directory string
	// AllowPull when set will pull images that are not present on
	// the daemon.
	AllowPull bool
	// IgnoreUnrecognizedInstructions, if true, allows instructions
	// that are not yet supported to be ignored (will be printed)
	IgnoreUnrecognizedInstructions bool
	// StrictVolumeOwnership if true will fail the build if a RUN
	// command follows a VOLUME command, since this client cannot
	// guarantee that the restored contents of the VOLUME directory
	// will have the right permissions.
	StrictVolumeOwnership bool
	// TransientMounts are a set of mounts from outside the build
	// to the inside that will not be part of the final image. Any
	// content created inside the mount's destinationPath will be
	// omitted from the final image.
	TransientMounts []Mount
	// The streams used for canonical output.
	Out, ErrOut io.Writer
	// AuthFn will handle authenticating any docker pulls if Image
	// is set to nil.
	AuthFn func(name string) ([]dockertypes.AuthConfig, bool)
	// LogFn is an optional command to log information to the end user
	LogFn func(format string, args ...interface{})
	// Deferred is a list of operations that must be cleaned up at
	// the end of execution. Use Release() to handle these.
	Deferred []func() error

	Stages    []*Stage
	lastStage uint8
}

// NewClientExecutor creates a client executor.
func NewClientExecutor(client *docker.Client) *ClientExecutor {
	e := &ClientExecutor{
		LogFn: func(string, ...interface{}) {},
	}
	if client != nil {
		e.AddStage(client)
	}
	return e
}

func (e *ClientExecutor) AddStage(client *docker.Client) {
	e.Stages = append(e.Stages, &Stage{
		Client:                  client,
		ContainerTransientMount: "/.imagebuilder-transient-mount",
	})
}

func (e *ClientExecutor) isMultiStage() bool {
	return len(e.Stages) > 1
}

func (e *ClientExecutor) CurrentStage() (*Stage, error) {
	l := len(e.Stages)
	if l == 0 {
		return nil, errors.New("there are not stages in executor")
	}
	return e.Stages[l-1], nil
}

func (e *ClientExecutor) DefaultExcludes() error {
	excludes, err := imagebuilder.ParseDockerignore(e.Directory)
	if err != nil {
		return err
	}
	e.Excludes = append(excludes, ".dockerignore")
	return nil
}

// Build is a helper method to perform a Docker build against the
// provided Docker client. It will load the image if not specified,
// create a container if one does not already exist, and start a
// container if the Dockerfile contains RUN commands. It will cleanup
// any containers it creates directly, and set the e.Image.ID field
// to the generated image.
func (e *ClientExecutor) Build(b *imagebuilder.Builder, node *parser.Node, from string) error {
	defer e.Release()
	if err := e.Prepare(b, node, from); err != nil {
		return err
	}
	if err := e.Execute(b, node); err != nil {
		return err
	}
	return e.Commit(b)
}

func (e *ClientExecutor) Prepare(b *imagebuilder.Builder, node *parser.Node, from string) error {
	var err error

	stage, err2 := e.CurrentStage()
	if err != nil {
		return err2
	}

	// identify the base image
	if len(from) == 0 {
		from, err = b.From(node)
		if err != nil {
			return err
		}
	}
	// load the image
	if stage.Image == nil || e.isMultiStage() {
		if from == imagebuilder.NoBaseImageSpecifier {
			if runtime.GOOS == "windows" {
				return fmt.Errorf("building from scratch images is not supported")
			}
			from, err = e.CreateScratchImage()
			if err != nil {
				return fmt.Errorf("unable to create a scratch image for this build: %v", err)
			}
			e.Deferred = append(e.Deferred, func() error { return stage.Client.RemoveImage(from) })
		}
		//log.Printf("AQUI: %s", e.Image)
		glog.V(4).Infof("Retrieving image %q", from)
		stage.Image, err = e.LoadImage(from)
		if err != nil {
			return err
		}
	}

	// update the builder with any information from the image, including ONBUILD
	// statements
	if err := b.FromImage(stage.Image, node); err != nil {
		return err
	}

	b.RunConfig.Image = from
	e.LogFn("FROM %s", from)
	glog.V(4).Infof("step: FROM %s", from)

	b.Excludes = e.Excludes

	var sharedMount string

	// create a container to execute in, if necessary
	mustStart := b.RequiresStart(node)
	if stage.Container == nil || e.isMultiStage() {
		opts := docker.CreateContainerOptions{
			Config: &docker.Config{
				Image: from,
			},
			HostConfig: &docker.HostConfig{},
		}
		if stage.HostConfig != nil {
			opts.HostConfig = stage.HostConfig
		}
		originalBinds := opts.HostConfig.Binds

		if mustStart || e.isMultiStage() {
			//log.Println("---------------- must start")
			// Transient mounts only make sense on images that will be running processes
			if len(e.TransientMounts) > 0 {
				volumeName, err := randSeq(imageSafeCharacters, 24)
				if err != nil {
					return err
				}
				v, err := stage.Client.CreateVolume(docker.CreateVolumeOptions{Name: volumeName})
				if err != nil {
					return fmt.Errorf("unable to create volume to mount secrets: %v", err)
				}
				e.Deferred = append(e.Deferred, func() error { return stage.Client.RemoveVolume(volumeName) })
				sharedMount = v.Mountpoint
				opts.HostConfig = &docker.HostConfig{
					Binds: []string{volumeName + ":" + stage.ContainerTransientMount},
				}
			}

			// TODO: windows support
			if len(stage.Command) > 0 {
				opts.Config.Cmd = stage.Command
				opts.Config.Entrypoint = nil
			} else {
				// TODO; replace me with a better default command
				opts.Config.Cmd = []string{"sleep 86400"}
				opts.Config.Entrypoint = []string{"/bin/sh", "-c"}
			}
		}

		if len(opts.Config.Cmd) == 0 {
			opts.Config.Entrypoint = []string{"/bin/sh", "-c", "# NOP"}
		}

		// copy any source content into the temporary mount path
		if mustStart && len(e.TransientMounts) > 0 {
			log.Println("----------- transient mounts")
			if len(sharedMount) == 0 {
				return fmt.Errorf("no mount point available for temporary mounts")
			}
			binds, err := e.PopulateTransientMounts(opts, e.TransientMounts, sharedMount)
			if err != nil {
				return err
			}
			opts.HostConfig.Binds = append(originalBinds, binds...)
		}

		container, err := stage.Client.CreateContainer(opts)
		if err != nil {
			return fmt.Errorf("unable to create build container: %v", err)
		}
		stage.Container = container
		e.Deferred = append([]func() error{func() error { return e.removeContainer(container.ID) }}, e.Deferred...)
	}

	// TODO: lazy start
	if mustStart && !stage.Container.State.Running {
		if err := stage.Client.StartContainer(stage.Container.ID, nil); err != nil {
			return fmt.Errorf("unable to start build container: %v", err)
		}
		stage.Container.State.Running = true
		// TODO: is this racy? may have to loop wait in the actual run step
	}
	return nil
}

// Execute performs all of the provided steps against the initialized container. May be
// invoked multiple times for a given container.
func (e *ClientExecutor) Execute(b *imagebuilder.Builder, node *parser.Node) error {
	for i, child := range node.Children {
		step := b.Step()
		if err := step.Resolve(child); err != nil {
			return err
		}
		glog.V(4).Infof("step: %s", step.Original)
		if e.LogFn != nil {
			// original may have unescaped %, so perform fmt escaping
			e.LogFn(strings.Replace(step.Original, "%", "%%", -1))
		}
		noRunsRemaining := !b.RequiresStart(&parser.Node{Children: node.Children[i+1:]})

		if err := b.Run(step, e, noRunsRemaining); err != nil {
			return err
		}
	}

	return nil
}

// Commit saves the completed build as an image with the provided tag. It will
// stop the container, commit the image, and then remove the container.
func (e *ClientExecutor) Commit(b *imagebuilder.Builder) error {
	config := b.Config()

	stage, err := e.CurrentStage()
	if err != nil {
		return err
	}
	if stage.Container.State.Running {
		glog.V(4).Infof("Stopping container %s ...", stage.Container.ID)
		if err := stage.Client.StopContainer(stage.Container.ID, 0); err != nil {
			return fmt.Errorf("unable to stop build container: %v", err)
		}
		stage.Container.State.Running = false
		// Starting the container may perform escaping of args, so to be consistent
		// we also set that here
		config.ArgsEscaped = true
	}

	var repository, tag string
	if len(stage.Tag) > 0 {
		repository, tag = docker.ParseRepositoryTag(stage.Tag)
		glog.V(4).Infof("Committing built container %s as image %q: %#v", stage.Container.ID, stage.Tag, config)
		if e.LogFn != nil {
			e.LogFn("Committing changes to %s ...", stage.Tag)
		}
	} else {
		glog.V(4).Infof("Committing built container %s: %#v", stage.Container.ID, config)
		if e.LogFn != nil {
			e.LogFn("Committing changes ...")
		}
	}

	defer func() {
		for _, err := range e.Release() {
			e.LogFn("Unable to cleanup: %v", err)
		}
	}()

	image, err := stage.Client.CommitContainer(docker.CommitContainerOptions{
		Author:     b.Author,
		Container:  stage.Container.ID,
		Run:        config,
		Repository: repository,
		Tag:        tag,
	})
	if err != nil {
		return fmt.Errorf("unable to commit build container: %v", err)
	}

	stage.Image = image
	glog.V(4).Infof("Committed %s to %s", stage.Container.ID, image.ID)

	if len(stage.Tag) > 0 {
		for _, s := range stage.AdditionalTags {
			repository, tag := docker.ParseRepositoryTag(s)
			err := stage.Client.TagImage(image.ID, docker.TagImageOptions{
				Repo: repository,
				Tag:  tag,
			})
			if err != nil {
				e.Deferred = append(e.Deferred, func() error {
					return stage.Client.RemoveImageExtended(image.ID, docker.RemoveImageOptions{Force: true})
				})
				return fmt.Errorf("unable to tag %q: %v", s, err)
			}
			e.LogFn("Tagged as %s", s)
		}
	}

	if e.LogFn != nil {
		e.LogFn("Done")
	}
	return nil
}

func (e *ClientExecutor) PopulateTransientMounts(opts docker.CreateContainerOptions, transientMounts []Mount, sharedMount string) ([]string, error) {
	stage, err := e.CurrentStage()
	if err != nil {
		return nil, err
	}
	container, err := stage.Client.CreateContainer(opts)
	if err != nil {
		return nil, fmt.Errorf("unable to create transient container: %v", err)
	}
	defer e.removeContainer(container.ID)

	var copies []imagebuilder.Copy
	for i, mount := range transientMounts {
		source := mount.SourcePath
		copies = append(copies, imagebuilder.Copy{
			FromFS: true,
			Src:    []string{source},
			Dest:   filepath.Join(stage.ContainerTransientMount, strconv.Itoa(i)),
		})
	}

	if err := e.CopyContainer(container, nil, copies...); err != nil {
		return nil, fmt.Errorf("unable to copy transient context into container: %v", err)
	}

	// mount individual items temporarily
	var binds []string
	for i, mount := range e.TransientMounts {
		binds = append(binds, fmt.Sprintf("%s:%s:%s", filepath.Join(sharedMount, strconv.Itoa(i)), mount.DestinationPath, "ro"))
	}
	return binds, nil
}

// Release deletes any items started by this executor.
func (e *ClientExecutor) Release() []error {
	stage, err := e.CurrentStage()
	if err != nil {
		return []error{err}
	}
	errs := stage.Volumes.Release()
	for _, fn := range e.Deferred {
		if err := fn(); err != nil {
			errs = append(errs, err)
		}
	}
	e.Deferred = nil
	return errs
}

// removeContainer removes the provided container ID
func (e *ClientExecutor) removeContainer(id string) error {
	stage, err := e.CurrentStage()
	if err != nil {
		return err
	}
	stage.Client.StopContainer(id, 0)
	err = stage.Client.RemoveContainer(docker.RemoveContainerOptions{
		ID:            id,
		RemoveVolumes: true,
		Force:         true,
	})
	if _, ok := err.(*docker.NoSuchContainer); err != nil && !ok {
		return fmt.Errorf("unable to cleanup container: %v", err)
	}
	return nil
}

// CreateScratchImage creates a new, zero byte layer that is identical to "scratch"
// except that the resulting image will have two layers.
func (e *ClientExecutor) CreateScratchImage() (string, error) {
	random, err := randSeq(imageSafeCharacters, 24)
	if err != nil {
		return "", err
	}
	name := fmt.Sprintf("scratch%s", random)

	buf := &bytes.Buffer{}
	w := tar.NewWriter(buf)
	w.Close()

	stage, err := e.CurrentStage()
	if err != nil {
		return "", err
	}
	return name, stage.Client.ImportImage(docker.ImportImageOptions{
		Repository:  name,
		Source:      "-",
		InputStream: buf,
	})
}

// imageSafeCharacters are characters allowed to be part of a Docker image name.
const imageSafeCharacters = "abcdefghijklmnopqrstuvwxyz0123456789"

// randSeq returns a sequence of random characters drawn from source. It returns
// an error if cryptographic randomness is not available or source is more than 255
// characters.
func randSeq(source string, n int) (string, error) {
	if len(source) > 255 {
		return "", fmt.Errorf("source must be less than 256 bytes long")
	}
	random := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", err
	}
	for i := range random {
		random[i] = source[random[i]%byte(len(source))]
	}
	return string(random), nil
}

// LoadImage checks the client for an image matching from. If not found,
// attempts to pull the image and then tries to inspect again.
func (e *ClientExecutor) LoadImage(from string) (*docker.Image, error) {
	stage, err := e.CurrentStage()
	if err != nil {
		return nil, err
	}

	image, err := stage.Client.InspectImage(from)
	if err == nil {
		return image, nil
	}
	if err != docker.ErrNoSuchImage {
		return nil, err
	}

	if !e.AllowPull {
		glog.V(4).Infof("image %s did not exist", from)
		return nil, docker.ErrNoSuchImage
	}

	repository, tag := docker.ParseRepositoryTag(from)
	if len(tag) == 0 {
		tag = "latest"
	}

	glog.V(4).Infof("attempting to pull %s with auth from repository %s:%s", from, repository, tag)

	// TODO: we may want to abstract looping over multiple credentials
	auth, _ := e.AuthFn(repository)
	if len(auth) == 0 {
		auth = append(auth, dockertypes.AuthConfig{})
	}

	if e.LogFn != nil {
		e.LogFn("Image %s was not found, pulling ...", from)
	}

	var lastErr error
	outputProgress := func(s string) {
		e.LogFn("%s", s)
	}
	for _, config := range auth {
		// TODO: handle IDs?
		pullWriter := imageprogress.NewPullWriter(outputProgress)
		defer pullWriter.Close()

		pullImageOptions := docker.PullImageOptions{
			Repository:    repository,
			Tag:           tag,
			OutputStream:  pullWriter,
			RawJSONStream: true,
		}
		if glog.V(5) {
			pullImageOptions.OutputStream = os.Stderr
			pullImageOptions.RawJSONStream = false
		}
		authConfig := docker.AuthConfiguration{Username: config.Username, ServerAddress: config.ServerAddress, Password: config.Password}
		if err = stage.Client.PullImage(pullImageOptions, authConfig); err == nil {
			break
		}
		lastErr = err
		continue
	}
	if lastErr != nil {
		return nil, fmt.Errorf("unable to pull image (from: %s, tag: %s): %v", repository, tag, lastErr)
	}

	return stage.Client.InspectImage(from)
}

func (e *ClientExecutor) Preserve(path string) error {
	stage, err := e.CurrentStage()
	if err != nil {
		return err
	}
	if stage.Volumes == nil {
		stage.Volumes = NewContainerVolumeTracker()
	}
	stage.Volumes.Add(path)
	return nil
}

func (e *ClientExecutor) UnrecognizedInstruction(step *imagebuilder.Step) error {
	if e.IgnoreUnrecognizedInstructions {
		e.LogFn("warning: Unknown instruction: %s", strings.ToUpper(step.Command))
		return nil
	}
	return fmt.Errorf("Unknown instruction: %s", strings.ToUpper(step.Command))
}

// Run executes a single Run command against the current container using exec().
// Since exec does not allow ENV or WORKINGDIR to be set, we force the execution of
// the user command into a shell and perform those operations before. Since RUN
// requires /bin/sh, we can use both 'cd' and 'export'.
func (e *ClientExecutor) Run(run imagebuilder.Run, config docker.Config) error {
	args := make([]string, len(run.Args))
	copy(args, run.Args)

	if runtime.GOOS == "windows" {
		if len(config.WorkingDir) > 0 {
			args[0] = fmt.Sprintf("cd %s && %s", imagebuilder.BashQuote(config.WorkingDir), args[0])
		}
		// TODO: implement windows ENV
		args = append([]string{"cmd", "/S", "/C"}, args...)
	} else {
		if len(config.WorkingDir) > 0 {
			args[0] = fmt.Sprintf("cd %s && %s", imagebuilder.BashQuote(config.WorkingDir), args[0])
		}
		if len(config.Env) > 0 {
			args[0] = imagebuilder.ExportEnv(config.Env) + args[0]
		}
		args = append([]string{"/bin/sh", "-c"}, args...)
	}

	stage, err := e.CurrentStage()
	if err != nil {
		return err
	}

	if e.StrictVolumeOwnership && !stage.Volumes.Empty() {
		return fmt.Errorf("a RUN command was executed after a VOLUME command, which may result in ownership information being lost")
	}
	if err := stage.Volumes.Save(stage.Container.ID, stage.TempDir, stage.Client); err != nil {
		return err
	}

	config.Cmd = args
	glog.V(4).Infof("Running %v inside of %s as user %s", config.Cmd, stage.Container.ID, config.User)
	exec, err := stage.Client.CreateExec(docker.CreateExecOptions{
		Cmd:          config.Cmd,
		Container:    stage.Container.ID,
		AttachStdout: true,
		AttachStderr: true,
		User:         config.User,
	})
	if err != nil {
		return err
	}
	if err := stage.Client.StartExec(exec.ID, docker.StartExecOptions{
		OutputStream: e.Out,
		ErrorStream:  e.ErrOut,
	}); err != nil {
		return err
	}
	status, err := stage.Client.InspectExec(exec.ID)
	if err != nil {
		return err
	}
	if status.ExitCode != 0 {
		return fmt.Errorf("running '%s' failed with exit code %d", strings.Join(args, " "), status.ExitCode)
	}

	if err := stage.Volumes.Restore(stage.Container.ID, stage.Client); err != nil {
		return err
	}

	return nil
}

// Copy implements the executor copy function.
func (e *ClientExecutor) Copy(excludes []string, copies ...imagebuilder.Copy) error {
	stage, err := e.CurrentStage()
	if err != nil {
		return err
	}
	// copying content into a volume invalidates the archived state of any given directory
	for _, copy := range copies {
		stage.Volumes.Invalidate(copy.Dest)
	}

	// TODO: create slice of copies with downloaded files, then copy them
	// TODO this is gibberish for now
	for _, copy := range copies {
		if copy.FromStage != "" {
			i, err := strconv.ParseUint(copy.FromStage, 10, 8)
			if err != nil {
				return err
			}
			// FIXME: implement function for this
			fromStage := e.Stages[i]
			//log.Printf("%s - %s\n", fromStage.Container.ID, stage.Container.ID)

			// Create temp file
			f, err := ioutil.TempFile("", fromStage.Container.ID)
			if err != nil {
				return err
			}

			// Download from container
			//log.Printf("%#v\n", copy.Src)
			err = fromStage.Client.DownloadFromContainer(fromStage.Container.ID, docker.DownloadFromContainerOptions{
				Path:         copy.Src[0],
				OutputStream: f,
			})
			if err != nil {
				return err
			}
			f.Close()

			// Upload to new container
			ff, err := os.Open(f.Name())
			if err != nil {
				return err
			}
			err = stage.Client.UploadToContainer(stage.Container.ID, docker.UploadToContainerOptions{
				InputStream: ff,
				Path:        copy.Dest,
			})
			ff.Close()

			//os.Remove(f.Name())
			log.Println(f.Name())
		}
	}

	return e.CopyContainer(stage.Container, excludes, copies...)
}

// CopyContainer copies the provided content into a destination container.
func (e *ClientExecutor) CopyContainer(container *docker.Container, excludes []string, copies ...imagebuilder.Copy) error {
	stage, err := e.CurrentStage()
	if err != nil {
		return err
	}

	for _, c := range copies {
		// TODO: reuse source
		for _, src := range c.Src {
			glog.V(4).Infof("Archiving %s %t", src, c.Download)

			//log.Printf("Archiving...: %s\n", c.Dest)

			// TODO
			// FIXME
			// primeiro ele faz o archive, depois faz o upload
			// hoje ta dando um erro the stat aqui pq ele nao encontra o src (que na verdade esta dentro de outro container)
			// TODO: arrumar e.Archive() pra acessar arquivo do container,fazer o DownloadFromContainer() e depois o UploadToContainer

			r, closer, err := e.Archive(c.FromFS, src, c.Dest, c.Download, excludes)
			if err != nil {
				return err
			}

			glog.V(5).Infof("Uploading to %s at %s", container.ID, c.Dest)
			//log.Printf("Uploading to %s at %s", container.ID, c.Dest)
			err = stage.Client.UploadToContainer(container.ID, docker.UploadToContainerOptions{
				InputStream: r,
				Path:        "/",
			})
			if err := closer.Close(); err != nil {
				glog.Errorf("Error while closing stream container copy stream %s: %v", container.ID, err)
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type closers []func() error

func (c closers) Close() error {
	var lastErr error
	for _, fn := range c {
		if err := fn(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// TODO: this does not support decompressing nested archives for ADD (when the source is a compressed file)
func (e *ClientExecutor) Archive(fromFS bool, src, dst string, allowDownload bool, excludes []string) (io.Reader, io.Closer, error) {
	stage, err := e.CurrentStage()
	if err != nil {
		return nil, nil, err
	}
	if isURL(src) {
		if !allowDownload {
			return nil, nil, fmt.Errorf("source can't be a URL")
		}
		return archiveFromURL(src, dst, stage.TempDir)
	}
	// the input is from the filesystem, use the source as the input
	if fromFS {
		return archiveFromDisk(src, ".", dst, allowDownload, excludes)
	}
	// if the context is in archive form, read from it without decompressing
	if len(stage.ContextArchive) > 0 {
		return archiveFromFile(stage.ContextArchive, src, dst, excludes)
	}
	// if the context is a directory, we only allow relative includes
	return archiveFromDisk(e.Directory, src, dst, allowDownload, excludes)
}

// ContainerVolumeTracker manages tracking archives of specific paths inside a container.
type ContainerVolumeTracker struct {
	paths map[string]string
	errs  []error
}

func NewContainerVolumeTracker() *ContainerVolumeTracker {
	return &ContainerVolumeTracker{
		paths: make(map[string]string),
	}
}

// Empty returns true if the tracker is not watching any paths
func (t *ContainerVolumeTracker) Empty() bool {
	return t == nil || len(t.paths) == 0
}

// Add tracks path unless it already is being tracked.
func (t *ContainerVolumeTracker) Add(path string) {
	if _, ok := t.paths[path]; !ok {
		t.paths[path] = ""
	}
}

// Release removes any stored snapshots
func (t *ContainerVolumeTracker) Release() []error {
	if t == nil {
		return nil
	}
	for path := range t.paths {
		t.ReleasePath(path)
	}
	return t.errs
}

func (t *ContainerVolumeTracker) ReleasePath(path string) {
	if t == nil {
		return
	}
	if archivePath, ok := t.paths[path]; ok && len(archivePath) > 0 {
		err := os.Remove(archivePath)
		if err != nil && !os.IsNotExist(err) {
			t.errs = append(t.errs, err)
		}
		glog.V(5).Infof("Releasing path %s (%v)", path, err)
		t.paths[path] = ""
	}
}

func (t *ContainerVolumeTracker) Invalidate(path string) {
	if t == nil {
		return
	}
	set := imagebuilder.VolumeSet{}
	set.Add(path)
	for path := range t.paths {
		if set.Covers(path) {
			t.ReleasePath(path)
		}
	}
}

// Save ensures that all paths tracked underneath this container are archived or
// returns an error.
func (t *ContainerVolumeTracker) Save(containerID, tempDir string, client *docker.Client) error {
	if t == nil {
		return nil
	}
	set := imagebuilder.VolumeSet{}
	for dest := range t.paths {
		set.Add(dest)
	}
	// remove archive paths that are covered by other paths
	for dest := range t.paths {
		if !set.Has(dest) {
			t.ReleasePath(dest)
			delete(t.paths, dest)
		}
	}
	for dest, archivePath := range t.paths {
		if len(archivePath) > 0 {
			continue
		}
		archivePath, err := snapshotPath(dest, containerID, tempDir, client)
		if err != nil {
			return err
		}
		t.paths[dest] = archivePath
	}
	return nil
}

// filterTarPipe transforms a tar file as it is streamed, calling fn on each header in the file.
// If fn returns false, the file is skipped. If an error occurs it is returned.
func filterTarPipe(w *tar.Writer, r *tar.Reader, fn func(*tar.Header) bool) error {
	for {
		h, err := r.Next()
		if err != nil {
			return err
		}
		if fn(h) {
			if err := w.WriteHeader(h); err != nil {
				return err
			}
			if _, err := io.Copy(w, r); err != nil {
				return err
			}
		} else {
			if _, err := io.Copy(ioutil.Discard, r); err != nil {
				return err
			}
		}
	}
}

// snapshotPath preserves the contents of path in container containerID as a temporary
// archive, returning either an error or the path of the archived file.
func snapshotPath(path, containerID, tempDir string, client *docker.Client) (string, error) {
	f, err := ioutil.TempFile(tempDir, "archived-path")
	if err != nil {
		return "", err
	}
	glog.V(4).Infof("Snapshot %s for later use under %s", path, f.Name())

	r, w := io.Pipe()
	tr := tar.NewReader(r)
	tw := tar.NewWriter(f)
	go func() {
		err := filterTarPipe(tw, tr, func(h *tar.Header) bool {
			if i := strings.Index(h.Name, "/"); i != -1 {
				h.Name = h.Name[i+1:]
			}
			return len(h.Name) > 0
		})
		if err == nil || err == io.EOF {
			tw.Flush()
			w.Close()
			glog.V(5).Infof("Snapshot rewritten from %s", path)
			return
		}
		glog.V(5).Infof("Snapshot of %s failed: %v", path, err)
		w.CloseWithError(err)
	}()

	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	err = client.DownloadFromContainer(containerID, docker.DownloadFromContainerOptions{
		Path:         path,
		OutputStream: w,
	})
	f.Close()
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// Restore ensures the paths managed by t exactly match the container. This requires running
// exec as a user that can delete contents from the container. It will return an error if
// any client operation fails.
func (t *ContainerVolumeTracker) Restore(containerID string, client *docker.Client) error {
	if t == nil {
		return nil
	}
	for dest, archivePath := range t.paths {
		if len(archivePath) == 0 {
			return fmt.Errorf("path %s does not have an archive and cannot be restored", dest)
		}
		glog.V(4).Infof("Restoring contents of %s from %s", dest, archivePath)
		if !strings.HasSuffix(dest, "/") {
			dest = dest + "/"
		}
		exec, err := client.CreateExec(docker.CreateExecOptions{
			Container: containerID,
			Cmd:       []string{"/bin/sh", "-c", "rm -rf $@", "", dest + "*"},
			User:      "0",
		})
		if err != nil {
			return fmt.Errorf("unable to setup clearing preserved path %s: %v", dest, err)
		}
		if err := client.StartExec(exec.ID, docker.StartExecOptions{}); err != nil {
			return fmt.Errorf("unable to clear preserved path %s: %v", dest, err)
		}
		status, err := client.InspectExec(exec.ID)
		if err != nil {
			return fmt.Errorf("clearing preserved path %s did not succeed: %v", dest, err)
		}
		if status.ExitCode != 0 {
			return fmt.Errorf("clearing preserved path %s failed with exit code %d", dest, status.ExitCode)
		}
		err = func() error {
			f, err := os.Open(archivePath)
			if err != nil {
				return fmt.Errorf("unable to open archive %s for preserved path %s: %v", archivePath, dest, err)
			}
			defer f.Close()
			if err := client.UploadToContainer(containerID, docker.UploadToContainerOptions{
				InputStream: f,
				Path:        dest,
			}); err != nil {
				return fmt.Errorf("unable to upload preserved contents from %s to %s: %v", archivePath, dest, err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}
