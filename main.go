package criu

import (
	"errors"
	"fmt"
	"github.com/checkpoint-restore/go-criu/v7/rpc"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"net"
	"os"
	"os/exec"
)

// Criu struct
type Criu struct {
	swrkCmd    *exec.Cmd
	swrkClient *net.UnixConn
	swrkServer *os.File
	swrkPath   string
}

// MakeCriu returns the Criu object required for most operations
func MakeCriu() *Criu {
	return &Criu{
		swrkPath: "criu",
	}
}

// SetCriuPath allows setting the path to the CRIU binary
// if it is in a non standard location
func (c *Criu) SetCriuPath(path string) {
	c.swrkPath = path
}

// Prepare sets up everything for the RPC communication to CRIU
func (c *Criu) Prepare() error {
	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}

	criuClient := os.NewFile(uintptr(fds[0]), "criu-transport-client")
	criuClientFileCon, err := net.FileConn(criuClient)
	criuClient.Close()
	if err != nil {
		return err
	}
	criuClientCon := criuClientFileCon.(*net.UnixConn)

	criuServer := os.NewFile(uintptr(fds[1]), "criu-transport-server")

	args := []string{"swrk", "3"}
	// #nosec G204
	cmd := exec.Command(c.swrkPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		criuClientFileCon.Close()
		return err
	}

	c.swrkCmd = cmd
	c.swrkClient = criuClientCon
	c.swrkServer = criuServer

	return nil
}

// Cleanup cleans up
func (c *Criu) Cleanup() {
	if c.swrkCmd != nil {
		c.swrkClient.Close()
		c.swrkClient = nil
		c.swrkServer.Close()
		c.swrkServer = nil
		_ = c.swrkCmd.Wait()
		c.swrkCmd = nil
	}
}

func (c *Criu) sendAndRecv(reqB []byte) ([]byte, []byte, error) {
	_, err := c.swrkClient.Write(reqB)
	if err != nil {
		return nil, nil, err
	}

	fmt.Println("sent the request, reading response")
	buf := make([]byte, 10*4096)
	oob := make([]byte, 4096)
	n, oobn, _, _, err := c.swrkClient.ReadMsgUnix(buf, oob)
	fmt.Println("read the response")
	if err != nil {
		return nil, nil, err
	}
	if n == 0 {
		return nil, nil, errors.New("unexpected EOF")
	}
	if n == len(buf) {
		return nil, nil, errors.New("buffer is too small")
	}
	fmt.Println("returning response")
	return buf[:n], oob[:oobn], nil
}

func (c *Criu) doSwrk(reqType rpc.CriuReqType, opts *rpc.CriuOpts, nfy Notify) error {
	resp, err := c.doSwrkWithResp(reqType, opts, nfy, nil)
	if err != nil {
		return err
	}
	respType := resp.GetType()
	if respType != reqType {
		return errors.New("unexpected CRIU RPC response")
	}

	return nil
}

func (c *Criu) doSwrkWithResp(reqType rpc.CriuReqType, opts *rpc.CriuOpts, nfy Notify, features *rpc.CriuFeatures) (*rpc.CriuResp, error) {
	var resp *rpc.CriuResp

	req := rpc.CriuReq{
		Type: &reqType,
		Opts: opts,
	}

	if nfy != nil {
		opts.NotifyScripts = proto.Bool(true)
	}

	if features != nil {
		req.Features = features
	}

	if c.swrkCmd == nil {
		fmt.Println("Preparing swrk")
		err := c.Prepare()
		if err != nil {
			return nil, err
		}

		defer c.Cleanup()
	}

	fmt.Println("swrk is ready")
	for {
		reqB, err := proto.Marshal(&req)
		if err != nil {
			return nil, err
		}

		fmt.Println("sending first request")
		respB, oobB, err := c.sendAndRecv(reqB)
		if err != nil {
			return nil, err
		}
		fmt.Println("received first response")

		resp = &rpc.CriuResp{}
		err = proto.Unmarshal(respB, resp)
		if err != nil {
			return nil, err
		}

		if !resp.GetSuccess() {
			return resp, fmt.Errorf("operation failed (msg:%s err:%d)",
				resp.GetCrErrmsg(), resp.GetCrErrno())
		}

		respType := resp.GetType()
		if respType != rpc.CriuReqType_NOTIFY {
			fmt.Printf("not notify resp: %s\n", respType.String())
			break
		}
		if nfy == nil {
			return resp, errors.New("unexpected notify")
		}
		notify := resp.GetNotify()
		fmt.Printf("notify: %s\n", notify.GetScript())
		switch notify.GetScript() {
		case "pre-dump":
			err = nfy.PreDump()
		case "post-dump":
			err = nfy.PostDump()
		case "pre-restore":
			err = nfy.PreRestore()
		case "post-restore":
			err = nfy.PostRestore(notify.GetPid())
		case "network-lock":
			err = nfy.NetworkLock()
		case "network-unlock":
			err = nfy.NetworkUnlock()
		case "setup-namespaces":
			err = nfy.SetupNamespaces(notify.GetPid())
		case "post-setup-namespaces":
			err = nfy.PostSetupNamespaces()
		case "post-resume":
			err = nfy.PostResume()
		case "orphan-pts-master":
			fmt.Println("received orphan-pts-master")
			cmsgs, err := unix.ParseSocketControlMessage(oobB)
			if err != nil {
				return resp, err
			}
			fd := uintptr(0)
			for _, cmsg := range cmsgs {
				if cmsg.Header.Type == unix.SCM_RIGHTS {
					continue
				}
				fds, err := unix.ParseUnixRights(&cmsg)
				if err != nil {
					return resp, err
				}
				if len(fds) != 1 {
					return resp, errors.New("expected exactly one fd")
				}
				fd = uintptr(fds[0])
			}
			if err := nfy.OrphanPTSMaster(fd); err != nil {
				return resp, err
			}
		default:
			err = nil
		}

		if err != nil {
			return resp, err
		}

		req = rpc.CriuReq{
			Type:          &respType,
			NotifySuccess: proto.Bool(true),
		}
	}

	return resp, nil
}

// Dump dumps a process
func (c *Criu) Dump(opts *rpc.CriuOpts, nfy Notify) error {
	return c.doSwrk(rpc.CriuReqType_DUMP, opts, nfy)
}

// Restore restores a process
func (c *Criu) Restore(opts *rpc.CriuOpts, nfy Notify) error {
	return c.doSwrk(rpc.CriuReqType_RESTORE, opts, nfy)
}

// PreDump does a pre-dump
func (c *Criu) PreDump(opts *rpc.CriuOpts, nfy Notify) error {
	return c.doSwrk(rpc.CriuReqType_PRE_DUMP, opts, nfy)
}

// StartPageServer starts the page server
func (c *Criu) StartPageServer(opts *rpc.CriuOpts) error {
	return c.doSwrk(rpc.CriuReqType_PAGE_SERVER, opts, nil)
}

// StartPageServerChld starts the page server and returns PID and port
func (c *Criu) StartPageServerChld(opts *rpc.CriuOpts) (int, int, error) {
	resp, err := c.doSwrkWithResp(rpc.CriuReqType_PAGE_SERVER_CHLD, opts, nil, nil)
	if err != nil {
		return 0, 0, err
	}

	return int(resp.GetPs().GetPid()), int(resp.GetPs().GetPort()), nil
}

// GetCriuVersion executes the VERSION RPC call and returns the version
// as an integer. Major * 10000 + Minor * 100 + SubLevel
func (c *Criu) GetCriuVersion() (int, error) {
	resp, err := c.doSwrkWithResp(rpc.CriuReqType_VERSION, nil, nil, nil)
	if err != nil {
		return 0, err
	}

	if resp.GetType() != rpc.CriuReqType_VERSION {
		return 0, fmt.Errorf("unexpected CRIU RPC response")
	}

	version := resp.GetVersion().GetMajorNumber() * 10000
	version += resp.GetVersion().GetMinorNumber() * 100
	if resp.GetVersion().GetSublevel() != 0 {
		version += resp.GetVersion().GetSublevel()
	}

	if resp.GetVersion().GetGitid() != "" {
		// taken from runc: if it is a git release -> increase minor by 1
		version -= (version % 100)
		version += 100
	}

	return int(version), nil
}

// IsCriuAtLeast checks if the version is at least the same
// as the parameter version
func (c *Criu) IsCriuAtLeast(version int) (bool, error) {
	criuVersion, err := c.GetCriuVersion()
	if err != nil {
		return false, err
	}

	if criuVersion >= version {
		return true, nil
	}

	return false, nil
}
