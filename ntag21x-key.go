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

// #include <freefare.h>
import "C"
import "unsafe"

// This structure wraps a Ntag21xKey.
type Ntag21xKey struct {
	key        C.NTAG21xKey
	*finalizee // TODO: ensure ok
}

func wrapNtag21xKey(k C.NTAG21xKey) *Ntag21xKey {
	if k == nil {
		panic("C.malloc() returned nil (out of memory)")
	}

	return &Ntag21xKey{key: k, finalizee: newFinalizee(unsafe.Pointer(k))}
}

// Create a new 3DES key. This function wraps the verbosely named function
// mifare_Ntag21x_3des_key_new_with_version. To get a result equal to what
// mifare_Ntag21x_3des_key_new does, set the version to 0 after creating the
// key or clear the lowest bits of the first eight bytes and set the lowest bits
// of the last eight using code like this:
//
//	var value [16]byte
//	/* ... */
//
//	for i := 0; i < 8; i++ {
//	    value[i] ^&= 1
//	}
//
//	for i := 8; i < 16; i++ {
//	    value[i] |= 1
//	}
//
//	key := NewNtag21xDES3Key(value)
//func NewNtag21xKey(value [16]byte) *Ntag21xKey { // TODO: ?
//	key := C.mifare_Ntag21x_3des_key_new_with_version((*C.uint8_t)(&value[0]))
//	return wrapNtag21xKey(key)
//}

// Create a new 3K3DES key. This function wraps the verbosely named function TODO: ?
// mifare_Ntag21x_3k3des_key_new_with_version. To get a result equal to what
// mifare_Ntag21x_3k3des_key_new does, set the version to 0 after creating the
// key or clear the lowest bit of each byte using code like this:
//
//	var value [24]byte
//	/* ... */
//
//	for i := 0; i < 8; i++ {
//	    value[i] ^&= 1
//	}
//
//	key := NewNtag21x3K3DESKey(value)
func NewNtag21xKey(value [24]byte) *Ntag21xKey {
	//key := C.mifare_Ntag21x_3k3des_key_new_with_version((*C.uint8_t)(&value[0]))
	key := C.ntag21x_key_new((*C.uint8_t)(&value[0])) // TODO: ?
	return wrapNtag21xKey(key)
}

// Create a new AES key. This function wraps the verbosely named function TODO: ?
// mifare_Ntag21x_aes_key_new_with_version. To get a result equal to what
// mifare_Ntag21x_aes_key_new does, pass 0 as version.
//func NewNtag21xAESKey(value [16]byte, version byte) *Ntag21xKey {
//	key := C.mifare_Ntag21x_aes_key_new_with_version((*C.uint8_t)(&value[0]), C.uint8_t(version))
//	return wrapNtag21xKey(key)
//}

//// Get the version of a Mifare Ntag21xKey. // TODO: ?
//func (k *Ntag21xKey) Version() byte {
//	return byte(C.mifare_Ntag21x_key_get_version(k.key))
//}
//
//// Set the version of a Mifare Ntag21xKey. // TODO: ?
//func (k *Ntag21xKey) SetVersion(version byte) {
//	C.mifare_Ntag21x_key_set_version(k.key, C.uint8_t(version))
//}

// Get a pointer to the wrapped MifareNtag21xKey structure. Be careful with this
// pointer: This wrapper deallocates the MifareNtag21xKey once the associated
// Ntag21xKey object becomes unreachable. Always keep a reference to the
// Ntag21xKey structure when doing fancy stuff with the pointer!
//
// For security reasons, this function returns an uintptr. Use the package
// unsafe to do something with it.
func (k *Ntag21xKey) Pointer() uintptr {
	return uintptr(unsafe.Pointer(k.key))
}
