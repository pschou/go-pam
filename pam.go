package pam

/*
#cgo LDFLAGS: -lpam
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <unistd.h>
#include <grp.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// Handle is a handle type to hang the PAM methods off of.
type Handle struct {
	Ptr unsafe.Pointer
}

func (hdl Handle) ptr() *C.pam_handle_t {
	return (*C.pam_handle_t)(hdl.Ptr)
}

// GetUser maps to the pam_get_user call, and returns the user that we're trying to auth as.
func (hdl Handle) GetUser() (string, error) {
	var usr *C.char
	if err := C.pam_get_user(hdl.ptr(), &usr, nil); err != C.PAM_SUCCESS {
		return "", pamError(err)
	}

	return C.GoString(usr), nil
}

// GetRemoteHost maps to the pam_get_rhost call, and returns the remote host.
func (hdl Handle) GetRemoteHost() (string, error) {
	var rhost unsafe.Pointer
	if err := C.pam_get_item(hdl.ptr(), C.PAM_RHOST, &rhost); err != C.PAM_SUCCESS {
		return "", pamError(err)
	}

	return C.GoString((*C.char)(rhost)), nil
}

// SetGroups maps to the setgroups call to set a users secondary groups.
func SetGroups(groups []int) error {
	gids := make([]C.gid_t, len(groups))
	for i, v := range groups {
		gids[i] = C.gid_t(v)
	}
	if err := C.setgroups(C.size_t(len(groups)), &gids[0]); err != C.PAM_SUCCESS {
		return pamError(err)
	}

	return nil
}

// GetGroups maps to the getgroups call to return the set secondary groups.
func GetGroups() (groups []int, err error) {
	cnt := C.getgroups(0, nil)
	if cnt > 0 {
		gids := make([]C.gid_t, cnt)
		if err := C.getgroups(cnt, &gids[0]); err < 0 {
			return nil, errors.New("GetGroups call failed")
		}
		groups = make([]int, cnt)
		for i, v := range gids {
			groups[i] = int(v)
		}
	}
	return
}

// Remove a group from the secondary group list
func DropGroup(group int) error {
	currentGroups, err := GetGroups()
	if err != nil || len(currentGroups) == 0 {
		return err
	}
	newGroups := make([]int, len(currentGroups)-1)
	found := 0
	for i, v := range currentGroups {
		if v == group {
			found++
		} else {
			newGroups[i-found] = v
		}
	}
	if found == 0 {
		// Don't need to do anything as the group is not set
		return nil
	}
	return SetGroups(newGroups[:len(currentGroups)-found])
}

// Add a group to the secondary group list
func AddGroup(group int) error {
	currentGroups, err := GetGroups()
	if err != nil {
		return err
	}
	for _, v := range currentGroups {
		if v == group {
			// Don't need to do anything as the group already exists
			return nil
		}
	}
	return SetGroups(append(currentGroups, group))
}

type pamError C.int

func (pe pamError) Error() string {
	return fmt.Sprintf("PAM error code %d", pe)
}
