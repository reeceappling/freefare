// Copyright (c) 2014, Robert Clausecker <fuzxxl@gmail.com>
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>

package freefare

/*
#include <stdlib.h>
#include <string.h>

// workaround: type is a reserved keyword, but ntag21x_version_info
// contains a member named type. Let's rename it to avoid trouble
#define type type_
#include <freefare.h>
#undef type
*/
import "C"

// Ntag21x cryptography modes. Compute the bitwise or of these constants and the TODO: ?
// key number to select a certain cryptography mode.
const (
	CryptoNTAG = 0x00
	//Crypto3k3DES = 0x40
	//CryptoAES    = 0x80
)

// Mifare DESFire communication modes TODO: ?
//const (
//	Plain      = 0x00
//	Maced      = 0x01
//	Enciphered = 0x03
//
//	// let the wrapper deduct the communication mode
//	Default = 0xff
//)

// Convert a Tag into an Ntag21xTag to access functionality available for
// Ntag21x tags. As opposed to the libfreefare itself, this wrapper does
// not provide data-level operations with explicit communication settings.
// Instead, the wrapper uses the settings stored in the Ntag21xTag struct or
// automatically detects them (as if the libfreefare non-ex function was called)
// if they are set to DEFAULT. When this wrapper creates a new Ntag21xTag,
// WriteSettings and ReadSettings are set to DEFAULT so each data access
// operation behaves like the underlying libfreefare function.
type Ntag21xTag struct {
	*tag

	// communication settings
	WriteSettings, ReadSettings byte // TODO: ensure ok
}

// Get last error. This function wraps ntag21x_last_error(). If
// no error has occured, this function returns nil.
func (t Ntag21xTag) LastError() error {
	err := Error(C.ntag21x_last_error(t.ctag))
	if err == 0 {
		return nil
	} else {
		return err
	}
}

//// Get last PICC error. This function wraps ntag21x_last_picc_error(). If TODO ?
//// no error has occured, this function returns nil.
//func (t Ntag21xTag) LastPICCError() error {
//	err := Error(C.ntag21x_last_picc_error(t.ctag))
//	if err == 0 {
//		return nil
//	} else {
//		return err
//	}
//}

//// Figure out what kind of error is hidden behind an EIO. This function largely TODO ?
//// replicates the behavior of freefare_strerror().
//func (t Ntag21xTag) resolveEIO() error {
//	err := t.Device().LastError()
//	if err != nil {
//		return err
//	}
//
//	err = t.LastPCDError()
//	if err != nil {
//		return err
//	}
//
//	err = t.LastPICCError()
//	if err != nil {
//		return err
//	}
//
//	return Error(UnknownError)
//}

// Connect to an Ntag21x tag. This causes the tag to be active.
func (t Ntag21xTag) Connect() error {
	r, err := C.ntag21x_connect(t.ctag)
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Disconnect from an Ntag21x tag. This causes the tag to be inactive.
func (t Ntag21xTag) Disconnect() error {
	r, err := C.ntag21x_disconnect(t.ctag)
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Authenticate to an Ntag21x tag. Notice that this wrapper does not
// provide wrappers for the ntag21x_authenticate_iso() and
// ntag21x_authenticate_aes() functions as the key type can be deducted
// from the key.
func (t Ntag21xTag) Authenticate(key Ntag21xKey) error {
	r, err := C.ntag21x_authenticate(t.ctag, key.key)
	if r == 0 {
		return nil
	}

	return t.TranslateError(err)
}

// Change the selected application settings to s. The application number of keys TODO: ?
// cannot be changed after the application has been created.
//func (t Ntag21xTag) ChangeKeySettings(s byte) error {
//	r, err := C.ntag21x_change_key_settings(t.ctag, C.uint8_t(s))
//	if r == 0 {
//		return nil
//	}
//
//	return t.TranslateError(err)
//}

// Return the key settings and maximum number of keys for the selected TODO: ?
// application.
//func (t Ntag21xTag) KeySettings() (settings, maxKeys byte, err error) {
//	var s, mk C.uint8_t
//	r, err := C.ntag21x_get_key_settings(t.ctag, &s, &mk)
//	if r != 0 {
//		return 0, 0, t.TranslateError(err)
//	}
//
//	settings = byte(s)
//	maxKeys = byte(mk)
//	err = nil
//	return
//}

// Change the key keyNo from oldKey to newKey. Depending on the application TODO: ?
// settings, a previous authentication with the same key or another key may be
// required.
//func (t Ntag21xTag) ChangeKey(keyNo byte, newKey, oldKey Ntag21xKey) error {
//	r, err := C.ntag21x_change_key(t.ctag, C.uint8_t(keyNo), newKey.key, oldKey.key)
//	if r == 0 {
//		return nil
//	}
//
//	return t.TranslateError(err)
//}

// Retrieve the version of the key keyNo for the selected application. TODO: ?
//func (t Ntag21xTag) KeyVersion(keyNo byte) (byte, error) {
//	var version C.uint8_t
//	r, err := C.ntag21x_get_key_version(t.ctag, C.uint8_t(keyNo), &version)
//	if r != 0 {
//		return 0, t.TranslateError(err)
//	}
//
//	return byte(version), nil
//}

// A Mifare DESFire directory file TODO ?
//type DESFireDF struct {
//	DESFireAid
//	Fid  uint16 // file ID
//	Name []byte // no longer than 16 bytes
//}

// Retrieve a list of directory file (df) names TODO: ?
//func (t Ntag21xTag) DFNames() ([]DESFireDF, error) {
//	var count C.size_t
//	var cdfs *C.MifareDESFireDF
//	r, err := C.ntag21x_get_df_names(t.ctag, &cdfs, &count)
//	if r != 0 {
//		return nil, t.TranslateError(err)
//	}
//
//	dfs := make([]DESFireDF, int(count))
//	dfsptr := uintptr(unsafe.Pointer(cdfs))
//	for i := range dfs {
//		dfptr := (*C.MifareDESFireDF)(unsafe.Pointer(dfsptr + uintptr(i)*unsafe.Sizeof(*cdfs)))
//		dfs[i] = DESFireDF{
//			NewDESFireAid(uint32(dfptr.aid)),
//			uint16(dfptr.fid),
//			C.GoBytes(unsafe.Pointer(&dfptr.df_name[0]), C.int(dfptr.df_name_len)),
//		}
//	}
//
//	C.free(unsafe.Pointer(dfsptr))
//	return dfs, nil
//}

// Reset t to factory defaults. For this function to work, a previous TODO: ?
// authentication with the card master key is required. WARNING: This function
// is irreversible and will delete all date on the card.
//func (t Ntag21xTag) FormatPICC() error {
//	r, err := C.ntag21x_format_picc(t.ctag)
//	if r != 0 {
//		return t.TranslateError(err)
//	}
//
//	return nil
//}

// Version information for an Ntag21x tag. // TODO: unsure if needed
//type Ntag21xVersionInfo struct {
//	Hardware, Software struct {
//		VendorID                   byte
//		Type, Subtype              byte
//		VersionMajor, VersionMinor byte
//		StorageSize                byte
//		Protocol                   byte
//	}
//
//	UID                            [7]byte
//	BatchNumber                    [5]byte
//	ProductionWeek, ProductionYear byte
//}

// Retrieve various information about t including UID. batch number, production // TODO: ?
// date, hardware and software information.
//func (t Ntag21xTag) Version() (Ntag21xVersionInfo, error) {
//	var ci C.struct_ntag21x_version_info
//	r, err := C.ntag21x_get_version(t.ctag, &ci)
//	if r != 0 {
//		return Ntag21xVersionInfo{}, t.TranslateError(err)
//	}
//
//	vi := Ntag21xVersionInfo{}
//
//	vih := &vi.Hardware
//	vih.VendorID = byte(ci.hardware.vendor_id)
//	vih.Type = byte(ci.hardware.type_)
//	vih.Subtype = byte(ci.hardware.subtype)
//	vih.VersionMajor = byte(ci.hardware.version_major)
//	vih.VersionMinor = byte(ci.hardware.version_minor)
//	vih.StorageSize = byte(ci.hardware.storage_size)
//	vih.Protocol = byte(ci.hardware.protocol)
//
//	vis := &vi.Software
//	vis.VendorID = byte(ci.software.vendor_id)
//	vis.Type = byte(ci.software.type_)
//	vis.Subtype = byte(ci.software.subtype)
//	vis.VersionMajor = byte(ci.software.version_major)
//	vis.VersionMinor = byte(ci.software.version_minor)
//	vis.StorageSize = byte(ci.software.storage_size)
//	vis.Protocol = byte(ci.software.protocol)
//
//	for i := range vi.UID {
//		vi.UID[i] = byte(ci.uid[i])
//	}
//
//	for i := range vi.BatchNumber {
//		vi.BatchNumber[i] = byte(ci.batch_number[i])
//	}
//
//	vi.ProductionWeek = byte(ci.production_week)
//	vi.ProductionYear = byte(ci.production_year)
//
//	return vi, nil
//}

// Get the amount of free memory on the PICC of an Ntag21x tag in bytes. // TODO: ?
//func (t Ntag21xTag) FreeMem() (uint32, error) {
//	var size C.uint32_t
//	r, err := C.ntag21x_free_mem(t.ctag, &size)
//	if r != 0 {
//		return 0, t.TranslateError(err)
//	}
//
//	return uint32(size), nil
//}

// This function can be used to deactivate the format function or to switch // TODO: ?
// to use a random UID.
//func (t Ntag21xTag) SetConfiguration(disableFormat, enableRandomUID bool) error {
//	// Notice that bool is a macro. the actual type is named _Bool.
//	r, err := C.ntag21x_set_configuration(
//		t.ctag, C._Bool(disableFormat), C._Bool(enableRandomUID))
//	if r != 0 {
//		return t.TranslateError(err)
//	}
//
//	return nil
//}

// Replace the ATS bytes returned by the PICC when it is selected. This function // TODO: ?
// performs the following extra test in order to ensure memory safety:
//
//	if len(ats) < int(ats[0]) {
//	    return Error(PARAMETER_ERROR)
//	}
//func (t Ntag21xTag) SetAts(ats []byte) error {
//	// ntag21x_set_ats reads ats[0] bytes out of ats, so it better
//	// had be that long.
//	if len(ats) < int(ats[0]) {
//		return Error(ParameterError)
//	}
//
//	r, err := C.ntag21x_set_ats(t.ctag, (*C.uint8_t)(&ats[0]))
//	if r != 0 {
//		return t.TranslateError(err)
//	}
//
//	return nil
//}

// Get the card's UID. This function can be used to get the original UID of the // TODO: ?
// target. The return value of
// CardUID() has the same format as the return value of UID(), but this function
// may fail.
func (t Ntag21xTag) CardUID() (string, error) {
	var startPage uint8 = 0
	var endPage uint8 = 2
	//var resultBytes *C.uint8_t
	var resultBytes = make([]byte, 3) // TODO: ?
	//var cString *C.char
	//&cString
	// TODO: read pages 0, 1, 2. Append them together, return as a string
	r, err := C.ntag21x_fast_read(t.ctag, C.uint8_t(startPage), C.uint8_t(endPage), (*C.uint8_t)(&resultBytes[0])) // TODO: ptr ok here?
	//defer C.free(unsafe.Pointer(resultBytes))
	if r != 0 {
		return "", t.TranslateError(err)
	}

	return string(resultBytes), nil // TODO: fix?
}

func (t Ntag21xTag) FastRead(startPage, endPage uint8) ([]byte, error) {
	//var resultBytes *C.uint8_t
	var resultBytes = make([]byte, endPage-startPage+1) // TODO: ?
	//var cString *C.char
	//&cString
	// TODO: read pages 0, 1, 2. Append them together, return as a string
	r, err := C.ntag21x_fast_read(t.ctag, C.uint8_t(startPage), C.uint8_t(endPage), (*C.uint8_t)(&resultBytes[0])) // TODO: ptr ok here?
	//defer C.free(unsafe.Pointer(resultBytes))
	if r != 0 {
		return nil, t.TranslateError(err)
	}

	return resultBytes, nil
}

func (t Ntag21xTag) Write(page byte, data [4]uint8) error {
	r, err := C.ntag21x_write(t.ctag, C.uint8_t(page), (*C.uint8_t)(&data[0]))
	if r != 0 {
		return t.TranslateError(err)
	}
	return nil
}

func (t Ntag21xTag) ReadUserData() ([]byte, error) {
	return t.FastRead(4, 39)
}

func (t Ntag21xTag) WriteUserData(data [144]byte) error {
	for i := 0; i < 36; i++ {
		var toWrite = [4]byte{}
		for j := range toWrite {
			toWrite[j] = data[(i*4)+j]
		}
		err := t.Write(uint8(i)+4, toWrite)
		if err != nil {
			return err // TODO: quick return or nah??
			// TODO: revert tag?
		}
	}
	return nil
}
