// Copyright 2014 <chaishushan{AT}gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//
// cgo pointer:
//
// Go1.3: Changes to the garbage collector
// http://golang.org/doc/go1.3#garbage_collector
//
// Go1.6:
// https://github.com/golang/proposal/blob/master/design/12416-cgo-pointers.md
//

package webp

/*
#cgo CFLAGS: -I./internal/libwebp/
#cgo CFLAGS: -I./internal/libwebp/src/
#cgo CFLAGS: -I./internal/include/
#cgo CFLAGS: -Wno-pointer-sign -DWEBP_USE_THREAD
#cgo !windows LDFLAGS: -lm

#include "webp.h"

#include <webp/decode.h>
#include <webp/encode.h>
#include <webp/mux.h>

#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

func webpGetInfo(data []byte) (width, height int, hasAlpha bool, err error) {
	if len(data) == 0 {
		err = errors.New("webpGetInfo: bad arguments, data is empty")
		return
	}
	if len(data) > maxWebpHeaderSize {
		data = data[:maxWebpHeaderSize]
	}

	var features C.WebPBitstreamFeatures
	if C.WebPGetFeatures((*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)), &features) != C.VP8_STATUS_OK {
		err = errors.New("C.WebPGetFeatures: failed")
		return
	}
	width, height = int(features.width), int(features.height)
	hasAlpha = (features.has_alpha != 0)
	return
}

func webpDecodeGray(data []byte) (pix []byte, width, height int, err error) {
	if len(data) == 0 {
		err = errors.New("webpDecodeGray: bad arguments")
		return
	}

	var cw, ch C.int
	var cptr = C.webpDecodeGray((*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)), &cw, &ch)
	if cptr == nil {
		err = errors.New("webpDecodeGray: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	pix = make([]byte, int(cw*ch*1))
	copy(pix, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(pix):len(pix)])
	width, height = int(cw), int(ch)
	return
}

func webpDecodeRGB(data []byte) (pix []byte, width, height int, err error) {
	if len(data) == 0 {
		err = errors.New("webpDecodeRGB: bad arguments")
		return
	}

	var cw, ch C.int
	var cptr = C.webpDecodeRGB((*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)), &cw, &ch)
	if cptr == nil {
		err = errors.New("webpDecodeRGB: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	pix = make([]byte, int(cw*ch*3))
	copy(pix, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(pix):len(pix)])
	width, height = int(cw), int(ch)
	return
}

func webpDecodeRGBA(data []byte) (pix []byte, width, height int, err error) {
	if len(data) == 0 {
		err = errors.New("webpDecodeRGBA: bad arguments")
		return
	}

	var cw, ch C.int
	var cptr = C.webpDecodeRGBA((*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)), &cw, &ch)
	if cptr == nil {
		err = errors.New("webpDecodeRGBA: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	pix = make([]byte, int(cw*ch*4))
	copy(pix, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(pix):len(pix)])
	width, height = int(cw), int(ch)
	return
}

func webpDecodeGrayToSize(data []byte, width, height int) (pix []byte, err error) {
	pix = make([]byte, int(width*height))
	stride := C.int(width)
	res := C.webpDecodeGrayToSize((*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)), C.int(width), C.int(height), stride, (*C.uint8_t)(unsafe.Pointer(&pix[0])))
	if res != C.VP8_STATUS_OK {
		pix = nil
		err = errors.New("webpDecodeGrayToSize: failed")
	}
	return
}

func webpDecodeRGBToSize(data []byte, width, height int) (pix []byte, err error) {
	pix = make([]byte, int(3*width*height))
	stride := C.int(3 * width)
	res := C.webpDecodeRGBToSize((*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)), C.int(width), C.int(height), stride, (*C.uint8_t)(unsafe.Pointer(&pix[0])))
	if res != C.VP8_STATUS_OK {
		pix = nil
		err = errors.New("webpDecodeRGBToSize: failed")
	}
	return
}

func webpDecodeRGBAToSize(data []byte, width, height int) (pix []byte, err error) {
	pix = make([]byte, int(4*width*height))
	stride := C.int(4 * width)
	res := C.webpDecodeRGBAToSize((*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)), C.int(width), C.int(height), stride, (*C.uint8_t)(unsafe.Pointer(&pix[0])))
	if res != C.VP8_STATUS_OK {
		pix = nil
		err = errors.New("webpDecodeRGBAToSize: failed")
	}
	return
}

func webpEncodeGray(pix []byte, width, height, stride int, quality float32) (output []byte, err error) {
	if len(pix) == 0 || width <= 0 || height <= 0 || stride <= 0 || quality < 0.0 {
		err = errors.New("webpEncodeGray: bad arguments")
		return
	}
	if stride < width*1 && len(pix) < height*stride {
		err = errors.New("webpEncodeGray: bad arguments")
		return
	}

	var cptr_size C.size_t
	var cptr = C.webpEncodeGray(
		(*C.uint8_t)(unsafe.Pointer(&pix[0])), C.int(width), C.int(height),
		C.int(stride), C.float(quality),
		&cptr_size,
	)
	if cptr == nil || cptr_size == 0 {
		err = errors.New("webpEncodeGray: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	output = make([]byte, int(cptr_size))
	copy(output, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(output):len(output)])
	return
}

func webpEncodeRGB(pix []byte, width, height, stride int, quality float32) (output []byte, err error) {
	if len(pix) == 0 || width <= 0 || height <= 0 || stride <= 0 || quality < 0.0 {
		err = errors.New("webpEncodeRGB: bad arguments")
		return
	}
	if stride < width*3 && len(pix) < height*stride {
		err = errors.New("webpEncodeRGB: bad arguments")
		return
	}

	var cptr_size C.size_t
	var cptr = C.webpEncodeRGB(
		(*C.uint8_t)(unsafe.Pointer(&pix[0])), C.int(width), C.int(height),
		C.int(stride), C.float(quality),
		&cptr_size,
	)
	if cptr == nil || cptr_size == 0 {
		err = errors.New("webpEncodeRGB: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	output = make([]byte, int(cptr_size))
	copy(output, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(output):len(output)])
	return
}

func webpEncodeRGBA(pix []byte, width, height, stride int, quality float32) (output []byte, err error) {
	if len(pix) == 0 || width <= 0 || height <= 0 || stride <= 0 || quality < 0.0 {
		err = errors.New("webpEncodeRGBA: bad arguments")
		return
	}
	if stride < width*4 && len(pix) < height*stride {
		err = errors.New("webpEncodeRGBA: bad arguments")
		return
	}

	var cptr_size C.size_t
	var cptr = C.webpEncodeRGBA(
		(*C.uint8_t)(unsafe.Pointer(&pix[0])), C.int(width), C.int(height),
		C.int(stride), C.float(quality),
		&cptr_size,
	)
	if cptr == nil || cptr_size == 0 {
		err = errors.New("webpEncodeRGBA: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	output = make([]byte, int(cptr_size))
	copy(output, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(output):len(output)])
	return
}

func webpEncodeLosslessGray(pix []byte, width, height, stride int) (output []byte, err error) {
	if len(pix) == 0 || width <= 0 || height <= 0 || stride <= 0 {
		err = errors.New("webpEncodeLosslessGray: bad arguments")
		return
	}
	if stride < width*1 && len(pix) < height*stride {
		err = errors.New("webpEncodeLosslessGray: bad arguments")
		return
	}

	var cptr_size C.size_t
	var cptr = C.webpEncodeLosslessGray(
		(*C.uint8_t)(unsafe.Pointer(&pix[0])), C.int(width), C.int(height),
		C.int(stride),
		&cptr_size,
	)
	if cptr == nil || cptr_size == 0 {
		err = errors.New("webpEncodeLosslessGray: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	output = make([]byte, int(cptr_size))
	copy(output, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(output):len(output)])
	return
}

func webpEncodeLosslessRGB(pix []byte, width, height, stride int) (output []byte, err error) {
	if len(pix) == 0 || width <= 0 || height <= 0 || stride <= 0 {
		err = errors.New("webpEncodeLosslessRGB: bad arguments")
		return
	}
	if stride < width*3 && len(pix) < height*stride {
		err = errors.New("webpEncodeLosslessRGB: bad arguments")
		return
	}

	var cptr_size C.size_t
	var cptr = C.webpEncodeLosslessRGB(
		(*C.uint8_t)(unsafe.Pointer(&pix[0])), C.int(width), C.int(height),
		C.int(stride),
		&cptr_size,
	)
	if cptr == nil || cptr_size == 0 {
		err = errors.New("webpEncodeLosslessRGB: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	output = make([]byte, int(cptr_size))
	copy(output, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(output):len(output)])
	return
}

func webpEncodeLosslessRGBA(exact int, pix []byte, width, height, stride int) (output []byte, err error) {
	if len(pix) == 0 || width <= 0 || height <= 0 || stride <= 0 {
		err = errors.New("webpEncodeLosslessRGBA: bad arguments")
		return
	}
	if stride < width*4 && len(pix) < height*stride {
		err = errors.New("webpEncodeLosslessRGBA: bad arguments")
		return
	}

	var cptr_size C.size_t
	var cptr = C.webpEncodeLosslessRGBA(
		C.int(exact), (*C.uint8_t)(unsafe.Pointer(&pix[0])), C.int(width), C.int(height),
		C.int(stride),
		&cptr_size,
	)
	if cptr == nil || cptr_size == 0 {
		err = errors.New("webpEncodeLosslessRGBA: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	output = make([]byte, int(cptr_size))
	copy(output, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(output):len(output)])
	return
}

func webpGetEXIF(data []byte) (metadata []byte, err error) {
	if len(data) == 0 {
		err = errors.New("webpGetEXIF: bad arguments")
		return
	}

	var cptr_size C.size_t
	var cptr = C.webpGetEXIF(
		(*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
		&cptr_size,
	)
	if cptr == nil || cptr_size == 0 {
		err = errors.New("webpGetEXIF: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	metadata = make([]byte, int(cptr_size))
	copy(metadata, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(metadata):len(metadata)])
	return
}
func webpGetICCP(data []byte) (metadata []byte, err error) {
	if len(data) == 0 {
		err = errors.New("webpGetICCP: bad arguments")
		return
	}

	var cptr_size C.size_t
	var cptr = C.webpGetICCP(
		(*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
		&cptr_size,
	)
	if cptr == nil || cptr_size == 0 {
		err = errors.New("webpGetICCP: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	metadata = make([]byte, int(cptr_size))
	copy(metadata, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(metadata):len(metadata)])
	return
}
func webpGetXMP(data []byte) (metadata []byte, err error) {
	if len(data) == 0 {
		err = errors.New("webpGetXMP: bad arguments")
		return
	}

	var cptr_size C.size_t
	var cptr = C.webpGetXMP(
		(*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
		&cptr_size,
	)
	if cptr == nil || cptr_size == 0 {
		err = errors.New("webpGetXMP: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	metadata = make([]byte, int(cptr_size))
	copy(metadata, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(metadata):len(metadata)])
	return
}
func webpGetMetadata(data []byte, format string) (metadata []byte, err error) {
	if len(data) == 0 {
		err = errors.New("webpGetMetadata: bad arguments")
		return
	}

	switch format {
	case "EXIF":
		return webpGetEXIF(data)
	case "ICCP":
		return webpGetICCP(data)
	case "XMP":
		return webpGetXMP(data)
	default:
		err = errors.New("webpGetMetadata: unknown format")
		return
	}
}

func webpSetEXIF(data, metadata []byte) (newData []byte, err error) {
	if len(data) == 0 || len(metadata) == 0 {
		err = errors.New("webpSetEXIF: bad arguments")
		return
	}

	var cptr_size C.size_t
	var cptr = C.webpSetEXIF(
		(*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
		(*C.char)(unsafe.Pointer(&metadata[0])), C.size_t(len(metadata)),
		&cptr_size,
	)
	if cptr == nil || cptr_size == 0 {
		err = errors.New("webpSetEXIF: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	newData = make([]byte, int(cptr_size))
	copy(newData, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(newData):len(newData)])
	return
}
func webpSetICCP(data, metadata []byte) (newData []byte, err error) {
	if len(data) == 0 || len(metadata) == 0 {
		err = errors.New("webpSetICCP: bad arguments")
		return
	}

	var cptr_size C.size_t
	var cptr = C.webpSetICCP(
		(*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
		(*C.char)(unsafe.Pointer(&metadata[0])), C.size_t(len(metadata)),
		&cptr_size,
	)
	if cptr == nil || cptr_size == 0 {
		err = errors.New("webpSetICCP: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	newData = make([]byte, int(cptr_size))
	copy(newData, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(newData):len(newData)])
	return
}
func webpSetXMP(data, metadata []byte) (newData []byte, err error) {
	if len(data) == 0 || len(metadata) == 0 {
		err = errors.New("webpSetXMP: bad arguments")
		return
	}

	var cptr_size C.size_t
	var cptr = C.webpSetXMP(
		(*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
		(*C.char)(unsafe.Pointer(&metadata[0])), C.size_t(len(metadata)),
		&cptr_size,
	)
	if cptr == nil || cptr_size == 0 {
		err = errors.New("webpSetXMP: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	newData = make([]byte, int(cptr_size))
	copy(newData, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(newData):len(newData)])
	return
}
func webpSetMetadata(data, metadata []byte, format string) (newData []byte, err error) {
	if len(data) == 0 || len(metadata) == 0 {
		err = errors.New("webpSetMetadata: bad arguments")
		return
	}

	switch format {
	case "EXIF":
		return webpSetEXIF(data, metadata)
	case "ICCP":
		return webpSetICCP(data, metadata)
	case "XMP":
		return webpSetXMP(data, metadata)
	default:
		err = errors.New("webpSetMetadata: unknown format")
		return
	}
}

func webpDelEXIF(data []byte) (newData []byte, err error) {
	if len(data) == 0 {
		err = errors.New("webpDelEXIF: bad arguments")
		return
	}

	var cptr_size C.size_t
	var cptr = C.webpDelEXIF(
		(*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
		&cptr_size,
	)
	if cptr == nil || cptr_size == 0 {
		err = errors.New("webpDelEXIF: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	newData = make([]byte, int(cptr_size))
	copy(newData, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(newData):len(newData)])
	return
}
func webpDelICCP(data []byte) (newData []byte, err error) {
	if len(data) == 0 {
		err = errors.New("webpDelICCP: bad arguments")
		return
	}

	var cptr_size C.size_t
	var cptr = C.webpDelICCP(
		(*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
		&cptr_size,
	)
	if cptr == nil || cptr_size == 0 {
		err = errors.New("webpDelICCP: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	newData = make([]byte, int(cptr_size))
	copy(newData, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(newData):len(newData)])
	return
}
func webpDelXMP(data []byte) (newData []byte, err error) {
	if len(data) == 0 {
		err = errors.New("webpDelXMP: bad arguments")
		return
	}

	var cptr_size C.size_t
	var cptr = C.webpDelXMP(
		(*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
		&cptr_size,
	)
	if cptr == nil || cptr_size == 0 {
		err = errors.New("webpDelXMP: failed")
		return
	}
	defer C.free(unsafe.Pointer(cptr))

	newData = make([]byte, int(cptr_size))
	copy(newData, ((*[1 << 30]byte)(unsafe.Pointer(cptr)))[0:len(newData):len(newData)])
	return
}

type WebPMuxError int

const (
	WebpMuxAbiVersion     = 0x0108
	WebpEncoderAbiVersion = 0x020f
)

const (
	WebpMuxOk              = WebPMuxError(C.WEBP_MUX_OK)
	WebpMuxNotFound        = WebPMuxError(C.WEBP_MUX_NOT_FOUND)
	WebpMuxInvalidArgument = WebPMuxError(C.WEBP_MUX_INVALID_ARGUMENT)
	WebpMuxBadData         = WebPMuxError(C.WEBP_MUX_BAD_DATA)
	WebpMuxMemoryError     = WebPMuxError(C.WEBP_MUX_MEMORY_ERROR)
	WebpMuxNotEnoughData   = WebPMuxError(C.WEBP_MUX_NOT_ENOUGH_DATA)
)

type WebPPicture C.WebPPicture
type WebPAnimEncoder C.WebPAnimEncoder
type WebPAnimEncoderOptions C.WebPAnimEncoderOptions
type WebPData C.WebPData
type WebPMux C.WebPMux
type WebPMuxAnimParams C.WebPMuxAnimParams
type webPConfig struct {
	webpConfig *C.WebPConfig
}

type WebPConfig interface {
	getRawPointer() *C.WebPConfig
	SetLossless(v int)
	GetLossless() int
	SetMethod(v int)
	SetImageHint(v int)
	SetTargetSize(v int)
	SetTargetPSNR(v float32)
	SetSegments(v int)
	SetSnsStrength(v int)
	SetFilterStrength(v int)
	SetFilterSharpness(v int)
	SetAutofilter(v int)
	SetAlphaCompression(v int)
	SetAlphaFiltering(v int)
	SetPass(v int)
	SetShowCompressed(v int)
	SetPreprocessing(v int)
	SetPartitions(v int)
	SetPartitionLimit(v int)
	SetEmulateJpegSize(v int)
	SetThreadLevel(v int)
	SetLowMemory(v int)
	SetNearLossless(v int)
	SetExact(v int)
	SetUseDeltaPalette(v int)
	SetUseSharpYuv(v int)
	SetAlphaQuality(v int)
	SetFilterType(v int)
	SetQuality(v float32)
}

func WebPDataClear(webPData *WebPData) {
	C.WebPDataClear((*C.WebPData)(unsafe.Pointer(webPData)))
}

func WebPMuxDelete(webPMux *WebPMux) {
	C.WebPMuxDelete((*C.WebPMux)(unsafe.Pointer(webPMux)))
}

func WebPPictureFree(webPPicture *WebPPicture) {
	C.WebPPictureFree((*C.WebPPicture)(unsafe.Pointer(webPPicture)))
}

func WebPAnimEncoderDelete(webPAnimEncoder *WebPAnimEncoder) {
	C.WebPAnimEncoderDelete((*C.WebPAnimEncoder)(unsafe.Pointer(webPAnimEncoder)))
}

func (wmap *WebPMuxAnimParams) SetBgcolor(v uint32) {
	((*C.WebPMuxAnimParams)(wmap)).bgcolor = (C.uint32_t)(v)
}

func (wmap *WebPMuxAnimParams) SetLoopCount(v int) {
	(*C.WebPMuxAnimParams)(wmap).loop_count = (C.int)(v)
}

func WebPPictureInit(webPPicture *WebPPicture) int {
	return int(C.WebPPictureInit((*C.WebPPicture)(unsafe.Pointer(webPPicture))))
}

func (wpp *WebPPicture) SetWidth(v int) {
	((*C.WebPPicture)(wpp)).width = (C.int)(v)
}

func (wpp *WebPPicture) SetHeight(v int) {
	((*C.WebPPicture)(wpp)).height = (C.int)(v)
}

func (wpp WebPPicture) GetWidth() int {
	return int(((C.WebPPicture)(wpp)).width)
}

func (wpp WebPPicture) GetHeight() int {
	return int(((C.WebPPicture)(wpp)).height)
}

func (wpp *WebPPicture) SetUseArgb(v int) {
	((*C.WebPPicture)(wpp)).use_argb = (C.int)(v)
}

func (wpd WebPData) GetBytes() []byte {
	return C.GoBytes(unsafe.Pointer(((C.WebPData)(wpd)).bytes), (C.int)(((C.WebPData)(wpd)).size))
}

func WebPDataInit(webPData *WebPData) {
	C.WebPDataInit((*C.WebPData)(unsafe.Pointer(webPData)))
}

// NewWebpConfig create webpconfig instance
func NewWebpConfig() WebPConfig {
	webpcfg := &webPConfig{}
	webpcfg.webpConfig = &C.WebPConfig{}
	WebPConfigInitInternal(webpcfg)
	return webpcfg
}

func WebPConfigInitInternal(config WebPConfig) int {
	return int(C.WebPConfigInitInternal(
		config.getRawPointer(),
		(C.WebPPreset)(0),
		(C.float)(75.0),
		(C.int)(WebpEncoderAbiVersion),
	))
}

func (webpCfg *webPConfig) getRawPointer() *C.WebPConfig {
	return webpCfg.webpConfig
}

func (webpCfg *webPConfig) SetLossless(v int) {
	webpCfg.webpConfig.lossless = (C.int)(v)
}

func (webpCfg *webPConfig) GetLossless() int {
	return int(webpCfg.webpConfig.lossless)
}

func (webpCfg *webPConfig) SetMethod(v int) {
	webpCfg.webpConfig.method = (C.int)(v)
}

func (webpCfg *webPConfig) SetImageHint(v int) {
	webpCfg.webpConfig.image_hint = (C.WebPImageHint)(v)
}

func (webpCfg *webPConfig) SetTargetSize(v int) {
	webpCfg.webpConfig.target_size = (C.int)(v)
}

func (webpCfg *webPConfig) SetTargetPSNR(v float32) {
	webpCfg.webpConfig.target_PSNR = (C.float)(v)
}

func (webpCfg *webPConfig) SetSegments(v int) {
	webpCfg.webpConfig.segments = (C.int)(v)
}

func (webpCfg *webPConfig) SetSnsStrength(v int) {
	webpCfg.webpConfig.sns_strength = (C.int)(v)
}

func (webpCfg *webPConfig) SetFilterStrength(v int) {
	webpCfg.webpConfig.filter_strength = (C.int)(v)
}

func (webpCfg *webPConfig) SetFilterSharpness(v int) {
	webpCfg.webpConfig.filter_sharpness = (C.int)(v)
}

func (webpCfg *webPConfig) SetAutofilter(v int) {
	webpCfg.webpConfig.autofilter = (C.int)(v)
}

func (webpCfg *webPConfig) SetAlphaCompression(v int) {
	webpCfg.webpConfig.alpha_compression = (C.int)(v)
}

func (webpCfg *webPConfig) SetAlphaFiltering(v int) {
	webpCfg.webpConfig.alpha_filtering = (C.int)(v)
}

func (webpCfg *webPConfig) SetPass(v int) {
	webpCfg.webpConfig.pass = (C.int)(v)
}

func (webpCfg *webPConfig) SetShowCompressed(v int) {
	webpCfg.webpConfig.show_compressed = (C.int)(v)
}

func (webpCfg *webPConfig) SetPreprocessing(v int) {
	webpCfg.webpConfig.preprocessing = (C.int)(v)
}

func (webpCfg *webPConfig) SetPartitions(v int) {
	webpCfg.webpConfig.partitions = (C.int)(v)
}

func (webpCfg *webPConfig) SetPartitionLimit(v int) {
	webpCfg.webpConfig.partition_limit = (C.int)(v)
}

func (webpCfg *webPConfig) SetEmulateJpegSize(v int) {
	webpCfg.webpConfig.emulate_jpeg_size = (C.int)(v)
}

func (webpCfg *webPConfig) SetThreadLevel(v int) {
	webpCfg.webpConfig.thread_level = (C.int)(v)
}

func (webpCfg *webPConfig) SetLowMemory(v int) {
	webpCfg.webpConfig.low_memory = (C.int)(v)
}

func (webpCfg *webPConfig) SetNearLossless(v int) {
	webpCfg.webpConfig.near_lossless = (C.int)(v)
}

func (webpCfg *webPConfig) SetExact(v int) {
	webpCfg.webpConfig.exact = (C.int)(v)
}

func (webpCfg *webPConfig) SetUseDeltaPalette(v int) {
	webpCfg.webpConfig.use_delta_palette = (C.int)(v)
}

func (webpCfg *webPConfig) SetUseSharpYuv(v int) {
	webpCfg.webpConfig.use_sharp_yuv = (C.int)(v)
}

func (webpCfg *webPConfig) SetAlphaQuality(v int) {
	webpCfg.webpConfig.alpha_quality = (C.int)(v)
}

func (webpCfg *webPConfig) SetFilterType(v int) {
	webpCfg.webpConfig.filter_type = (C.int)(v)
}

func (webpCfg *webPConfig) SetQuality(v float32) {
	webpCfg.webpConfig.quality = (C.float)(v)
}

func (encOptions *WebPAnimEncoderOptions) GetAnimParams() WebPMuxAnimParams {
	return WebPMuxAnimParams(((*C.WebPAnimEncoderOptions)(encOptions)).anim_params)
}

func (encOptions *WebPAnimEncoderOptions) SetAnimParams(v WebPMuxAnimParams) {
	((*C.WebPAnimEncoderOptions)(encOptions)).anim_params = (C.WebPMuxAnimParams)(v)
}

func (encOptions *WebPAnimEncoderOptions) SetMinimizeSize(v int) {
	((*C.WebPAnimEncoderOptions)(encOptions)).minimize_size = (C.int)(v)
}

func (encOptions *WebPAnimEncoderOptions) SetKmin(v int) {
	((*C.WebPAnimEncoderOptions)(encOptions)).kmin = (C.int)(v)
}

func (encOptions *WebPAnimEncoderOptions) SetKmax(v int) {
	((*C.WebPAnimEncoderOptions)(encOptions)).kmax = (C.int)(v)
}

func (encOptions *WebPAnimEncoderOptions) SetAllowMixed(v int) {
	((*C.WebPAnimEncoderOptions)(encOptions)).allow_mixed = (C.int)(v)
}

func (encOptions *WebPAnimEncoderOptions) SetVerbose(v int) {
	((*C.WebPAnimEncoderOptions)(encOptions)).verbose = (C.int)(v)
}

func WebPAnimEncoderOptionsInitInternal(webPAnimEncoderOptions *WebPAnimEncoderOptions) int {
	return int(C.WebPAnimEncoderOptionsInitInternal(
		(*C.WebPAnimEncoderOptions)(unsafe.Pointer(webPAnimEncoderOptions)),
		(C.int)(WebpMuxAbiVersion),
	))
}

func WebPPictureImportRGBA(data []byte, stride int, webPPicture *WebPPicture) error {
	res := int(C.WebPPictureImportRGBA(
		(*C.WebPPicture)(unsafe.Pointer(webPPicture)),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		(C.int)(stride),
	))
	if res == 0 {
		return errors.New("error: WebPPictureImportBGRA")
	}
	return nil
}

func WebPAnimEncoderNewInternal(width, height int, webPAnimEncoderOptions *WebPAnimEncoderOptions) *WebPAnimEncoder {
	return (*WebPAnimEncoder)(C.WebPAnimEncoderNewInternal(
		(C.int)(width),
		(C.int)(height),
		(*C.WebPAnimEncoderOptions)(unsafe.Pointer(webPAnimEncoderOptions)),
		(C.int)(WebpMuxAbiVersion),
	))
}

func WebPAnimEncoderAdd(webPAnimEncoder *WebPAnimEncoder, webPPicture *WebPPicture, timestamp int, webpcfg WebPConfig) int {
	return int(C.WebPAnimEncoderAdd(
		(*C.WebPAnimEncoder)(unsafe.Pointer(webPAnimEncoder)),
		(*C.WebPPicture)(unsafe.Pointer(webPPicture)),
		(C.int)(timestamp),
		webpcfg.getRawPointer(),
	))
}

func WebPAnimEncoderAssemble(webPAnimEncoder *WebPAnimEncoder, webPData *WebPData) int {
	return int(C.WebPAnimEncoderAssemble(
		(*C.WebPAnimEncoder)(unsafe.Pointer(webPAnimEncoder)),
		(*C.WebPData)(unsafe.Pointer(webPData)),
	))
}

func WebPMuxCreateInternal(webPData *WebPData, copyData int) *WebPMux {
	return (*WebPMux)(C.WebPMuxCreateInternal(
		(*C.WebPData)(unsafe.Pointer(webPData)),
		(C.int)(copyData),
		(C.int)(WebpMuxAbiVersion),
	))
}

func WebPMuxSetAnimationParams(webPMux *WebPMux, webPMuxAnimParams *WebPMuxAnimParams) WebPMuxError {
	return (WebPMuxError)(C.WebPMuxSetAnimationParams(
		(*C.WebPMux)(unsafe.Pointer(webPMux)),
		(*C.WebPMuxAnimParams)(unsafe.Pointer(webPMuxAnimParams)),
	))
}

func WebPMuxGetAnimationParams(webPMux *WebPMux, webPMuxAnimParams *WebPMuxAnimParams) WebPMuxError {
	return (WebPMuxError)(C.WebPMuxGetAnimationParams(
		(*C.WebPMux)(unsafe.Pointer(webPMux)),
		(*C.WebPMuxAnimParams)(unsafe.Pointer(webPMuxAnimParams)),
	))
}

func WebPMuxAssemble(webPMux *WebPMux, webPData *WebPData) WebPMuxError {
	return (WebPMuxError)(C.WebPMuxAssemble(
		(*C.WebPMux)(unsafe.Pointer(webPMux)),
		(*C.WebPData)(unsafe.Pointer(webPData)),
	))
}
