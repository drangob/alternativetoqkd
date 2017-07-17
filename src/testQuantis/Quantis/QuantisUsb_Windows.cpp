/*
 * Quantis USB Library for Windows
 *
 * Copyright (C) 2004-2012 ID Quantique SA, Carouge/Geneva, Switzerland
 * All rights reserved.
 *
 * ----------------------------------------------------------------------------
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY.
 *
 * ----------------------------------------------------------------------------
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License version 2 as published by the Free Software 
 * Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 * ----------------------------------------------------------------------------
 *
 * For history of changes, see ChangeLog.txt
 */

/* 
 * NOTE: This file must have a .cpp extension since Visual Studio *MUST* 
 *       compile it with the C++ compiler, otherwise the code won't compile
 *       due to missing C99 standards in MS C compiler.
 */


#ifndef DISABLE_QUANTIS_USB

#ifndef _WIN32
# error "This module is for Windows only!"
#endif


#include <stdlib.h> 
#include <windows.h>

/* Includes WinUSB (from Windows DDK)
 *
 *  Add following directories for include files:
 *     C:\WinDDK\7600.16385.0\inc\api
 *     C:\WinDDK\7600.16385.0\inc\ddk winusb
 *
 *  Also add following directories for library files:
 *     C:\WinDDK\7600.16385.0\lib\wlh\i386 for Win32 platforms
 *     C:\WinDDK\7600.16385.0\lib\wlh\amd64 for x86 platforms
 */
#include <setupapi.h>
#pragma comment(lib, "setupapi.lib") 

#include <winusb.h>
//#pragma comment(lib, "winusb.lib")

#include <malloc.h>

#include "Quantis.h"
#include "Quantis_Internal.h"
#include "QuantisUsb_Commands.h"


#pragma warning(disable: 4200)

/* Hardcoded driver version */
#define DRIVER_VERSION  2.1f

/* --------------------- USB constants and structures --------------------- */

// Data transfer direction
#define DIRECTION_MASK                        0x80
#define DIRECTION_HOST_TO_DEVICE              0x00
#define DIRECTION_DEVICE_TO_HOST              0x80

// Types
#define TYPE_MASK                             0x60
#define TYPE_STANDARD                         0x00
#define TYPE_CLASS                            0x20
#define TYPE_VENDOR                           0x40

// Recipients                   
#define RECIPIENT_MASK                        0x1F
#define RECIPIENT_DEVICE                      0x00
#define RECIPIENT_INTERFACE                   0x01
#define RECIPIENT_ENDPOINT                    0x02
#define RECIPIENT_OTHER                       0x03


/**
 * USB Device Descriptor Structure
 */
typedef struct _USB_DEV_DSC
{
  unsigned char bLength;
  unsigned char bDscType;
  unsigned short bcdUSB;
  unsigned char bDevCls;
  unsigned char bDevSubCls;
  unsigned char bDevProtocol;
  unsigned char bMaxPktSize0;  
  unsigned short idVendor;
  unsigned short idProduct;
  unsigned short bcdDevice;
  unsigned char iMFR;
  unsigned char iProduct;
  unsigned char iSerialNum; 
  unsigned char bNumCfg;
} USB_DEV_DSC;


/**
 * USB Configuration Descriptor Structure
 */
typedef struct _USB_STR_DSC
{
  unsigned char bLength;
  unsigned char bDscType;
  WCHAR string[];
} USB_STR_DSC;


/**
 * QuantisDeviceHandlePrivateData for Quantis USB on Windows
 */
typedef struct QuantisPrivateData
{
  HANDLE deviceHandle;
  USB_DEV_DSC deviceInfo;
  WINUSB_INTERFACE_HANDLE winUsbDeviceHandle;
  HINSTANCE hInstanceWinUsb;
  char serialNumber[256];
  char manufacturer[256];
} QuantisPrivateData;


typedef BOOL (__stdcall *Quantis_WinUsb_ControlTransfer)(WINUSB_INTERFACE_HANDLE,
                                               WINUSB_SETUP_PACKET,
                                               PUCHAR,
                                               ULONG,
                                               PULONG,
                                               LPOVERLAPPED);

typedef BOOL (__stdcall *Quantis_WinUsb_Free)(WINUSB_INTERFACE_HANDLE);

typedef BOOL (__stdcall *Quantis_WinUsb_GetDescriptor)(WINUSB_INTERFACE_HANDLE,
                                             UCHAR,
                                             UCHAR,
                                             USHORT,
                                             PUCHAR,
                                             ULONG,
                                             PULONG);

typedef BOOL (__stdcall *Quantis_WinUsb_Initialize)(HANDLE,
                                          PWINUSB_INTERFACE_HANDLE);

typedef BOOL (__stdcall *Quantis_WinUsb_QueryPipe)(WINUSB_INTERFACE_HANDLE,
                                         UCHAR,
                                         UCHAR,
                                         PWINUSB_PIPE_INFORMATION);

typedef BOOL (__stdcall *Quantis_WinUsb_ReadPipe)(WINUSB_INTERFACE_HANDLE,
                                        UCHAR,
                                        PUCHAR,
                                        ULONG,
                                        PULONG,
                                        LPOVERLAPPED);

typedef BOOL (__stdcall *Quantis_WinUsb_SetPipePolicy)(WINUSB_INTERFACE_HANDLE,
                                             UCHAR,
                                             ULONG,
                                             ULONG,
                                             PVOID);

/* --------------------------- Internal Methods --------------------------- */

inline int QuantisUsbGetIntValue(QuantisDeviceHandle* deviceHandle, UCHAR request)
{
  QuantisPrivateData* _privateData = (QuantisPrivateData*)deviceHandle->privateData;
  
  int buffer;

  WINUSB_SETUP_PACKET setupPacket;
  setupPacket.RequestType = TYPE_VENDOR | 
                            RECIPIENT_INTERFACE | 
                            DIRECTION_DEVICE_TO_HOST;
  setupPacket.Request = request;
  setupPacket.Value = 0;
  setupPacket.Index = 0;
  setupPacket.Length = sizeof(buffer);
  
  ULONG resultSize = 0;

  Quantis_WinUsb_ControlTransfer _WinUsb_ControlTransfer = (Quantis_WinUsb_ControlTransfer)
    GetProcAddress(_privateData->hInstanceWinUsb, "WinUsb_ControlTransfer");

  if(!_WinUsb_ControlTransfer)
  {
    return QUANTIS_ERROR_IO;
  }

  if(!_WinUsb_ControlTransfer(_privateData->winUsbDeviceHandle,
                              setupPacket,
                              (PUCHAR)&buffer,
                              sizeof(buffer),
                              &resultSize,
                              NULL))
  {
    return QUANTIS_ERROR_IO;
  }

  return buffer;
}

inline int QuantisUsbGetUCHARValue(QuantisDeviceHandle* deviceHandle, UCHAR request)
{
  QuantisPrivateData* _privateData = (QuantisPrivateData*)deviceHandle->privateData;
  
  UCHAR buffer;

  WINUSB_SETUP_PACKET setupPacket;
  setupPacket.RequestType = TYPE_VENDOR | 
                            RECIPIENT_INTERFACE | 
                            DIRECTION_DEVICE_TO_HOST;
  setupPacket.Request = request;
  setupPacket.Value = 0;
  setupPacket.Index = 0;
  setupPacket.Length = sizeof(buffer);
  
  ULONG resultSize = 0;
  
  Quantis_WinUsb_ControlTransfer _WinUsb_ControlTransfer = (Quantis_WinUsb_ControlTransfer)
    GetProcAddress(_privateData->hInstanceWinUsb, "WinUsb_ControlTransfer");

  if(!_WinUsb_ControlTransfer)
  {
    return QUANTIS_ERROR_IO;
  }

  if(!_WinUsb_ControlTransfer(_privateData->winUsbDeviceHandle,
                              setupPacket,
                              &buffer,
                              sizeof(buffer),
                              &resultSize,
                              NULL))
  {
    return QUANTIS_ERROR_IO;
  }

  return buffer;
}

inline int QuantisUsbSendRequest(QuantisDeviceHandle* deviceHandle, UCHAR request)
{
  QuantisPrivateData* _privateData = (QuantisPrivateData*)deviceHandle->privateData;

  WINUSB_SETUP_PACKET setupPacket;
  setupPacket.RequestType = TYPE_VENDOR | 
                            RECIPIENT_INTERFACE | 
                            DIRECTION_HOST_TO_DEVICE;
  setupPacket.Request = request;
  setupPacket.Value = 0;
  setupPacket.Index = 0;
  setupPacket.Length = 0;
  
  ULONG resultSize = 0;

  Quantis_WinUsb_ControlTransfer _WinUsb_ControlTransfer = (Quantis_WinUsb_ControlTransfer)
    GetProcAddress(_privateData->hInstanceWinUsb, "WinUsb_ControlTransfer");

  if(!_WinUsb_ControlTransfer)
  {
    return QUANTIS_ERROR_IO;
  }

  if(!_WinUsb_ControlTransfer(_privateData->winUsbDeviceHandle,
                              setupPacket,
                              NULL,
                              0,
                              &resultSize,
                              NULL))
  {
    return QUANTIS_ERROR_IO;
  }
  
  return QUANTIS_SUCCESS;
}

/* -------------------------- QuantisUsb Methods -------------------------- */


/* Board reset */
int QuantisUsbBoardReset(QuantisDeviceHandle* deviceHandle)
{
# define USB_RESET_BUFFER_SIZE 4096
  char buffer[USB_RESET_BUFFER_SIZE];
  
  if ((QuantisUsbGetModulesStatus(deviceHandle) != 0x0001) ||
      (QuantisUsbGetModulesMask(deviceHandle) != 0x0000))
  {
    QuantisUsbModulesDisable(deviceHandle, 0xFFFFFFFF);
    QuantisUsbModulesEnable(deviceHandle, 0xFFFFFFFF);
    Sleep(1000);
  }

  return QuantisUsbRead(deviceHandle, buffer, USB_RESET_BUFFER_SIZE);
}


/* Close */
void QuantisUsbClose(QuantisDeviceHandle* deviceHandle)
{
  QuantisPrivateData* _privateData = (QuantisPrivateData*)deviceHandle->privateData;
  if (!_privateData)
  {
    return;
  }

  if (_privateData->winUsbDeviceHandle)
  {
    Quantis_WinUsb_Free _WinUsb_Free = (Quantis_WinUsb_Free)GetProcAddress(_privateData->hInstanceWinUsb, "WinUsb_Free");

    if(_WinUsb_Free)
    {
      _WinUsb_Free(_privateData->winUsbDeviceHandle);
      _privateData->winUsbDeviceHandle = NULL;
    }
  }

  if (_privateData->hInstanceWinUsb)
  {
    FreeLibrary(_privateData->hInstanceWinUsb);
    _privateData->hInstanceWinUsb = NULL;
  }

  if (_privateData->deviceHandle != INVALID_HANDLE_VALUE)
  {
    CloseHandle(_privateData->deviceHandle);
  }

  free(_privateData);
  _privateData = NULL;
}


/* Count */
int QuantisUsbCount()
{
  /* 
   * Build a list of all devices (with the specified GUID) that are present in
   * the system that have enabled an interface from the storage volume device 
   * interface class.
   */
  HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_QUANTIS_USB, 
                                          NULL, 
                                          NULL, 
                                          DIGCF_PRESENT | DIGCF_INTERFACEDEVICE);
  if (hDevInfo == INVALID_HANDLE_VALUE)
  {
    /* No device found */
    return 0;
  }

  /* 
   * Enumerate the system's device interfaces and obtains information on our 
   * device interface
   */
  SP_DEVICE_INTERFACE_DATA devInfoData;
  SecureZeroMemory(&devInfoData, sizeof(devInfoData));
  devInfoData.cbSize = sizeof(devInfoData);

  LONG result;
  int memberIndex = 0;
  while(true)
  {
    result = SetupDiEnumDeviceInterfaces(hDevInfo, 
                                         0, 
                                         &GUID_DEVINTERFACE_QUANTIS_USB, 
                                         memberIndex, 
                                         &devInfoData);
    if(result)
    {
      memberIndex++;
    }
    else
    {
      break;
    }
  }

  /* We don't allow more than MAX_QUANTIS_DEVICE */
  if (memberIndex > MAX_QUANTIS_DEVICE)
  {
    return MAX_QUANTIS_DEVICE;
  }
  else
  {
    return memberIndex;
  }
}


/* GetBoardVersion */
int QuantisUsbGetBoardVersion(QuantisDeviceHandle* deviceHandle)
{
  return QuantisUsbGetIntValue(deviceHandle, QUANTIS_USB_CMD_GET_BOARD_VERSION);
}


/* GetDriverVersion */
float QuantisUsbGetDriverVersion()
{
  return DRIVER_VERSION;
}


/* GetManufacturer */
char* QuantisUsbGetManufacturer(QuantisDeviceHandle* deviceHandle)
{
  QuantisPrivateData* _privateData = (QuantisPrivateData*)deviceHandle->privateData;

  return _privateData->manufacturer;
}


/* GetModulesMask */
int QuantisUsbGetModulesMask(QuantisDeviceHandle* deviceHandle)
{
  return QuantisUsbGetUCHARValue(deviceHandle, QUANTIS_USB_CMD_GET_MODULES_MASK);
}


/* GetModulesDataRate */
int QuantisUsbGetModulesDataRate(QuantisDeviceHandle* deviceHandle)
{
  int modulesRate = QuantisUsbGetIntValue(deviceHandle, QUANTIS_USB_CMD_GET_MODULES_RATE);
  
  if (modulesRate < 0)
  {
    return modulesRate;
  }
  /* loaded modules rate is in kbit/s. Converting in Bytes per second */
  modulesRate = modulesRate * 1000 / 8;
  
  int modulesMask = QuantisUsbGetModulesMask(deviceHandle);
  if (modulesMask < 0)
  {
    return modulesMask;
  }

  return modulesRate * QuantisCountSetBits(modulesMask);
}


/* GetModulesPower */
int QuantisUsbGetModulesPower(QuantisDeviceHandle* deviceHandle)
{
  return QuantisUsbGetUCHARValue(deviceHandle, QUANTIS_USB_CMD_GET_MODULES_POWER);
}


/* GetModulesStatus */
int QuantisUsbGetModulesStatus(QuantisDeviceHandle* deviceHandle)
{
  return QuantisUsbGetUCHARValue(deviceHandle, QUANTIS_USB_CMD_GET_MODULES_STATUS);
}


/* GetSerialNumber */
char* QuantisUsbGetSerialNumber(QuantisDeviceHandle* deviceHandle)
{
  QuantisPrivateData* _privateData = (QuantisPrivateData*)deviceHandle->privateData;
  
  return _privateData->serialNumber;
}


/* ModulesDisable */
int QuantisUsbModulesDisable(QuantisDeviceHandle* deviceHandle, int moduleMask)
{
  if ((moduleMask & 0x0001) != (0x0001))
  {
    /* Quantis USB only has one module... */
    return QUANTIS_ERROR_INVALID_PARAMETER;
  }
  
  return QuantisUsbSendRequest(deviceHandle, QUANTIS_USB_CMD_MODULE_DISABLE);
}


/* ModulesEnable */
int QuantisUsbModulesEnable(QuantisDeviceHandle* deviceHandle, int moduleMask)
{
  if ((moduleMask & 0x0001) != (0x0001))
  {
    /* Quantis USB only has one module... */
    return QUANTIS_ERROR_INVALID_PARAMETER;
  }
  
  return QuantisUsbSendRequest(deviceHandle, QUANTIS_USB_CMD_MODULE_ENABLE);
}



/* Open */
int QuantisUsbOpen(QuantisDeviceHandle* deviceHandle)
{
  /* 
   * Build a list of all devices (with the specified GUID) that are present in
   * the system that have enabled an interface from the storage volume device 
   * interface class.
   */
  HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_QUANTIS_USB, 
                                          NULL, 
                                          NULL, 
                                          DIGCF_PRESENT | DIGCF_INTERFACEDEVICE);
  if (hDevInfo == INVALID_HANDLE_VALUE)
  {
    return QUANTIS_ERROR_NO_DEVICE;
  }

  /*
   * Enumerate the system's device interfaces and obtains information on our 
   * device interface
   */
  SP_DEVICE_INTERFACE_DATA devInfoData;
  devInfoData.cbSize = sizeof(devInfoData);
  PSP_DEVICE_INTERFACE_DETAIL_DATA detailData = NULL;

  DWORD length = 0;
  DWORD required = 0;

  if(!SetupDiEnumDeviceInterfaces(hDevInfo, 
                                  0, 
                                  &GUID_DEVINTERFACE_QUANTIS_USB,
                                  deviceHandle->deviceNumber, 
                                  &devInfoData))
  {
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return QUANTIS_ERROR_NO_DEVICE;
  }
  
  /* 
   * Get the required buffer size.
   * 
   * Note that this function returns the required buffer size in length 
   * variable and fails with GetLastError returning ERROR_INSUFFICIENT_BUFFER.
   */
  SetupDiGetDeviceInterfaceDetail(hDevInfo, 
                                  &devInfoData, 
                                  NULL, 
                                  0, 
                                  &length, 
                                  NULL);

  detailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)alloca(length);
  detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

  /* Returns details about a device interface */
  if(!SetupDiGetDeviceInterfaceDetail(hDevInfo, 
                                      &devInfoData, 
                                      detailData, 
                                      length, 
                                      &required, 
                                      NULL))
  {
    /* Destroy data */
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return QUANTIS_ERROR_IO;
  }

  /* Destroy not more useful data */
  SetupDiDestroyDeviceInfoList(hDevInfo);

  /* Allocate memory for private data */
  QuantisPrivateData* _privateData = (QuantisPrivateData*)malloc(sizeof(QuantisPrivateData));
  if (!_privateData)
  {
    return QUANTIS_ERROR_NO_MEMORY;
  }

  /* Obtain a file handle for the device */
  _privateData->deviceHandle = CreateFile(detailData->DevicePath, 
                                          GENERIC_READ | GENERIC_WRITE, 
                                          0, 
                                          (LPSECURITY_ATTRIBUTES)NULL,
                                          OPEN_EXISTING, 
                                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, 
                                          NULL);

  if (_privateData->deviceHandle == INVALID_HANDLE_VALUE)
  {
    //free(_privateData);
    //return QUANTIS_ERROR_IO;
    goto Cleanup_PrivateData;
  }
  
  /* Obtains a module handle on WinUsb.dll */
  _privateData->hInstanceWinUsb = LoadLibrary(L"WinUSB.dll");
  if (!_privateData->hInstanceWinUsb)
  {
    //CloseHandle(_privateData->deviceHandle);
    //free(_privateData);
    //return QUANTIS_ERROR_IO;
    goto Cleanup_DeviceHandle;
  }

  /* Obtains a WinUSB handle for the device */
  PWINUSB_INTERFACE_HANDLE pwinUsbDeviceHandle = &(_privateData->winUsbDeviceHandle);
  Quantis_WinUsb_Initialize _WinUsb_Initialize = (Quantis_WinUsb_Initialize)
    GetProcAddress(_privateData->hInstanceWinUsb, "WinUsb_Initialize");

  if(!_WinUsb_Initialize)
  {
    goto Cleanup_Library;
  }

  if (!_WinUsb_Initialize(_privateData->deviceHandle, pwinUsbDeviceHandle))
  {
  //  CloseHandle(_privateData->deviceHandle);
  //  free(_privateData);
  //  return QUANTIS_ERROR_IO;
    goto Cleanup_Library;
  }

  /* Obtains a requested descriptor */
  DWORD dwBytesReturned = 0;
  Quantis_WinUsb_GetDescriptor _WinUsb_GetDescriptor = (Quantis_WinUsb_GetDescriptor)
    GetProcAddress(_privateData->hInstanceWinUsb, "WinUsb_GetDescriptor");

  if(!_WinUsb_GetDescriptor)
  {
    goto Cleanup_Library;
  }

  if(!_WinUsb_GetDescriptor(_privateData->winUsbDeviceHandle,
                            USB_DEVICE_DESCRIPTOR_TYPE,
                            0,
                            0x0409,
                            (PUCHAR)&_privateData->deviceInfo,
                            sizeof(_privateData->deviceInfo),
                            &dwBytesReturned))
  {
    //CloseHandle(_privateData->deviceHandle);
    //free(_privateData);
    //return QUANTIS_ERROR_IO;
    goto Cleanup_Library;
  }


  /* Get product's serial number */
  static unsigned char serialNumber[256];
  USB_STR_DSC* serialNumberStrDsc = (USB_STR_DSC*)serialNumber;

  if(!_WinUsb_GetDescriptor(_privateData->winUsbDeviceHandle,
                            USB_STRING_DESCRIPTOR_TYPE,
                            _privateData->deviceInfo.iSerialNum,
                            0x0409,
                            serialNumber,
                            sizeof(serialNumber),
                            &dwBytesReturned))
  {
    size_t serialNumberLength = strlen(QUANTIS_NO_SERIAL);
    memcpy(_privateData->serialNumber, QUANTIS_NO_SERIAL, serialNumberLength);
    _privateData->serialNumber[serialNumberLength] = 0;
  }
  else
  {
    size_t pReturnValue;
    unsigned char serialNumberLength = (serialNumberStrDsc->bLength - 2) / 2;
    wcstombs_s(&pReturnValue, 
               _privateData->serialNumber,
               sizeof(_privateData->serialNumber),
               serialNumberStrDsc->string,
               sizeof(WCHAR) * serialNumberLength);
    _privateData->serialNumber[serialNumberLength] = 0;
  }


  /* Get manufacturer */
  static unsigned char manufacturer[256];
  USB_STR_DSC* manufacturerStrDsc = (USB_STR_DSC*)manufacturer;

  if(!_WinUsb_GetDescriptor(_privateData->winUsbDeviceHandle,
                            USB_STRING_DESCRIPTOR_TYPE,
                            _privateData->deviceInfo.iMFR,
                            0x0409,
                            manufacturer,
                            sizeof(manufacturer),
                            &dwBytesReturned))
  {
    size_t manufacturerLength = strlen(QUANTIS_NOT_AVAILABLE);
    memcpy(_privateData->manufacturer, QUANTIS_NOT_AVAILABLE, manufacturerLength);
    _privateData->manufacturer[manufacturerLength] = 0;
  }
  else
  {
    size_t pReturnValue;
    unsigned char manufacturerLength = (manufacturerStrDsc->bLength - 2) / 2;
    wcstombs_s(&pReturnValue,
               _privateData->manufacturer,
               sizeof(_privateData->manufacturer),
               manufacturerStrDsc->string,
               sizeof(WCHAR) * manufacturerLength);
    _privateData->manufacturer[manufacturerLength] = 0;
  }

  
  deviceHandle->privateData = _privateData;

  return QUANTIS_SUCCESS;


  /* Cleanup on error */
Cleanup_Library:
  FreeLibrary(_privateData->hInstanceWinUsb);

Cleanup_DeviceHandle:
  CloseHandle(_privateData->deviceHandle);

Cleanup_PrivateData:
  free(_privateData);
  
  /* Return an error code */
  return QUANTIS_ERROR_IO;
}


/* Read */
int QuantisUsbRead(QuantisDeviceHandle* deviceHandle, void* buffer, size_t size)
{
  QuantisPrivateData* _privateData = (QuantisPrivateData*)deviceHandle->privateData;

  /* Check if at least one module is present/enabled */
  if (QuantisUsbGetModulesStatus(deviceHandle) <= 0)
  {
    return QUANTIS_ERROR_NO_MODULE;
  }

  /* Get information about a pipe that is associated with above interface */
  WINUSB_PIPE_INFORMATION pipeInfo;

  Quantis_WinUsb_QueryPipe _WinUsb_QueryPipe = (Quantis_WinUsb_QueryPipe)
    GetProcAddress(_privateData->hInstanceWinUsb, "WinUsb_QueryPipe");

  if(!_WinUsb_QueryPipe)
  {
    return QUANTIS_ERROR_IO;
  }

  if(!_WinUsb_QueryPipe(_privateData->winUsbDeviceHandle, 
                        0, 
                        (UCHAR)0, 
                        &pipeInfo))
  {
    return QUANTIS_ERROR_IO;
  }

  /* Verify that the pipe type is set to the correct USBD_PIPE_TYPE */
  if (pipeInfo.PipeType != UsbdPipeTypeBulk) 
  { 
    return QUANTIS_ERROR_IO;
  }

  /* Set the transfer time-out interval */
  ULONG timeout = QUANTIS_USB_REQUEST_TIMEOUT; /* in milliseconds */
  
  Quantis_WinUsb_SetPipePolicy _WinUsb_SetPipePolicy = (Quantis_WinUsb_SetPipePolicy)
    GetProcAddress(_privateData->hInstanceWinUsb, "WinUsb_SetPipePolicy");

  if(!_WinUsb_SetPipePolicy)
  {
    return QUANTIS_ERROR_IO;
  }

  if (!_WinUsb_SetPipePolicy(_privateData->winUsbDeviceHandle,
                             pipeInfo.PipeId, 
                             PIPE_TRANSFER_TIMEOUT,
                             sizeof(timeout), 
                             &timeout))
  {
    return QUANTIS_ERROR_IO;
  }

  char tempBuffer[USB_MAX_BULK_PACKET_SIZE];
  ULONG readBytes = 0;
  
  Quantis_WinUsb_ReadPipe _WinUsb_ReadPipe = (Quantis_WinUsb_ReadPipe)
    GetProcAddress(_privateData->hInstanceWinUsb, "WinUsb_ReadPipe");

  if(!_WinUsb_ReadPipe)
  {
    return QUANTIS_ERROR_IO;
  }

  while(readBytes < size)
  {
    size_t chunkSize = size - readBytes;
    if (chunkSize > USB_MAX_BULK_PACKET_SIZE)
    {
      chunkSize = USB_MAX_BULK_PACKET_SIZE;
    }

    /* Read data */
    ULONG resultSize;
    if (!_WinUsb_ReadPipe(_privateData->winUsbDeviceHandle,
                          pipeInfo.PipeId, 
                          (PUCHAR)tempBuffer,
                          (ULONG)chunkSize,
                          &resultSize,
                          NULL))
    {
      return QUANTIS_ERROR_IO;
    }

    /* Copy data to user's buffer */
    memcpy((char*)buffer + readBytes, tempBuffer, resultSize);

    readBytes += resultSize;
  }

  return readBytes;
}


/* GetBusDeviceId */
int QuantisUsbGetBusDeviceId(QuantisDeviceHandle* deviceHandle)
{
  //only implemented with Unix PCI
  return 0;
}

#endif /* DISABLE_QUANTIS_USB */
