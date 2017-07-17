/*
 * Quantis PCI Library for Windows
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

#ifndef DISABLE_QUANTIS_PCI

#ifndef _WIN32
# error "This module is for Windows only!"
#endif


/* Exclude rarely-used stuff from Windows headers */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <malloc.h>
#include <setupapi.h>
#pragma comment(lib, "setupapi.lib")

//#include <stdio.h> // printf
#include <winioctl.h>

#include "Quantis.h"
#include "Quantis_Internal.h"

#include "../Drivers/Windows/QuantisPci/src/common/Public.h"



/**
 * QuantisPrivateData for Quantis PCI on Unix systems
 */
typedef struct QuantisPrivateData
{
  HANDLE deviceHandle; /* Device handle */
} QuantisPrivateData;


int QuantisPciIoCtl(QuantisDeviceHandle* deviceHandle, 
                    DWORD ioControlCode,
                    void* inBuffer,
                    DWORD inBufferSize,
                    void* outBuffer, 
                    DWORD outBufferSize)
{
  QuantisPrivateData* _privateData = (QuantisPrivateData*)deviceHandle->privateData;
  DWORD bytesReturned;
  if(!DeviceIoControl( _privateData->deviceHandle,
                      ioControlCode,
                      inBuffer,
                      inBufferSize,
                      outBuffer,
                      outBufferSize,
                      &bytesReturned,
                      NULL))
  {
    return QUANTIS_ERROR_IO;
  }

  if (bytesReturned != outBufferSize)
  {
    return QUANTIS_ERROR_IO;
  }

  return QUANTIS_SUCCESS;
}


/* Board reset */
int QuantisPciBoardReset(QuantisDeviceHandle* deviceHandle)
{
  return QuantisPciIoCtl(deviceHandle, 
                         QUANTIS_IOCTL_RESET_BOARD, 
                         NULL, 
                         0, 
                         NULL, 
                         0);
}


/* Close */
void QuantisPciClose(QuantisDeviceHandle* deviceHandle)
{
  QuantisPrivateData* _privateData = (QuantisPrivateData*)deviceHandle->privateData;
  if (!_privateData)
  {
    return;
  }

  if (_privateData->deviceHandle != INVALID_HANDLE_VALUE)
  {
    CloseHandle(_privateData->deviceHandle);
  }

  free(_privateData);
  _privateData = NULL;
}


/* Count */
int QuantisPciCount()
{
  HDEVINFO hDevInfo;
  SP_DEVICE_INTERFACE_DATA devInfoData;
  LONG result;
  int memberIndex = 0;
  /* 
   * Build a list of all devices (with the specified GUID) that are present in
   * the system that have enabled an interface from the storage volume device 
   * interface class.
   */
  hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_QUANTIS_PCI, 
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
  SecureZeroMemory(&devInfoData, sizeof(devInfoData));
  devInfoData.cbSize = sizeof(devInfoData);

  while(1)
  {
    result = SetupDiEnumDeviceInterfaces(hDevInfo, 
                                         0, 
                                         &GUID_DEVINTERFACE_QUANTIS_PCI, 
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
int QuantisPciGetBoardVersion(QuantisDeviceHandle* deviceHandle)
{
  int boardVersion;
  int result;

  result = QuantisPciIoCtl(deviceHandle,
                           QUANTIS_IOCTL_GET_BOARD_VERSION,
                           NULL, 
                           0,
                           &boardVersion,
                           sizeof(boardVersion));
  if (result < 0)
  {
    return result;
  }
  else
  {
    return boardVersion;
  }
}


/* GetDriverVersion */
float QuantisPciGetDriverVersion()
{
  int result;
  int deviceNumber = 0;
  int driverVersion = 0;
  QuantisDeviceHandle* deviceHandle = NULL;

  /* Open device */
  result = QuantisOpenInternal(QUANTIS_DEVICE_PCI, deviceNumber, &deviceHandle);
  if (result < 0)
  {
    /* Assumes there is no card installed */
    return 0.0f;
  }

  /* Perform request */
  result = QuantisPciIoCtl(deviceHandle,
                           QUANTIS_IOCTL_GET_DRIVER_VERSION,
                           NULL, 
                           0,
                           &driverVersion,
                           sizeof(driverVersion));
  if (result < 0)
  {
    /* Assumes there is no card installed */
    driverVersion = 0;
  }

  /* Close device */
  QuantisCloseInternal(deviceHandle);

  return ((float)driverVersion) / 10.0f;
}


/* GetManufacturer */
char* QuantisPciGetManufacturer(QuantisDeviceHandle* deviceHandle)
{
  deviceHandle = deviceHandle; /* Avoids unused parameter warning */
  /* Quantis PCI do not support manufacturer retrieval */
  return (char*)QUANTIS_NOT_AVAILABLE;
}


/* GetModulesMask */
int QuantisPciGetModulesMask(QuantisDeviceHandle* deviceHandle)
{
  int modulesMask;
  int result;

  result = QuantisPciIoCtl(deviceHandle,
                           QUANTIS_IOCTL_GET_MODULES_MASK,
                           NULL, 
                           0,
                           &modulesMask,
                           sizeof(modulesMask));
  if (result < 0)
  {
    return result;
  }
  else
  {
    return modulesMask;
  }
}


/* GetModulesDataRate */
int QuantisPciGetModulesDataRate(QuantisDeviceHandle* deviceHandle)
{
  int modulesMask = QuantisPciGetModulesMask(deviceHandle);
  return QUANTIS_MODULE_DATA_RATE * QuantisCountSetBits(modulesMask);
}


/* GetModulesPower */
int QuantisPciGetModulesPower(QuantisDeviceHandle* deviceHandle)
{
  deviceHandle = deviceHandle; /* Avoids unused parameter warning */

  /* PCI modules are always powered */
  return 1;
}


/* GetModulesStatus */
int QuantisPciGetModulesStatus(QuantisDeviceHandle* deviceHandle)
{
  int modulesStatus;
  int result;

  result = QuantisPciIoCtl(deviceHandle,
                           QUANTIS_IOCTL_GET_MODULES_STATUS,
                           NULL, 
                           0,
                           &modulesStatus,
                           sizeof(modulesStatus));
  if (result < 0)
  {
    return result;
  }
  else
  {
    return modulesStatus;
  }
}


/* GetSerialNumber */
char* QuantisPciGetSerialNumber(QuantisDeviceHandle* deviceHandle)
{
  deviceHandle = deviceHandle; /* Avoids unused parameter warning */
  /* Quantis PCI do not support serial number retrieval */
  return (char*)QUANTIS_NO_SERIAL;
}


/* ModulesDisable */
int QuantisPciModulesDisable(QuantisDeviceHandle* deviceHandle, int moduleMask)
{
  return QuantisPciIoCtl(deviceHandle,
                         QUANTIS_IOCTL_DISABLE_MODULE,
                         (void*)moduleMask,
                         sizeof(moduleMask),
                         NULL, 
                         0);
}


/* ModulesEnable */
int QuantisPciModulesEnable(QuantisDeviceHandle* deviceHandle, int moduleMask)
{
  return QuantisPciIoCtl(deviceHandle,
                         QUANTIS_IOCTL_ENABLE_MODULE,
                         (void*)moduleMask,
                         sizeof(moduleMask),
                         NULL, 
                         0);
}


/* Open */
int QuantisPciOpen(QuantisDeviceHandle* deviceHandle)
{
  SP_DEVICE_INTERFACE_DATA devInfoData;
  HDEVINFO hDevInfo;
  PSP_DEVICE_INTERFACE_DETAIL_DATA detailData = NULL;
  DWORD length = 0;
  DWORD required = 0;
  QuantisPrivateData* _privateData = NULL;

  /* Retrieve the device information for all Quantis devices */
  hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_QUANTIS_PCI,
                                 NULL,
                                 NULL,
                                 DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
  if(hDevInfo == INVALID_HANDLE_VALUE) 
  {
    /* No device present in the system */
    return QUANTIS_ERROR_NO_DEVICE;
  }

  /*
   * Enumerate the system's device interfaces and obtains information on our 
   * device interface
   */
  devInfoData.cbSize = sizeof(devInfoData);

  if(!SetupDiEnumDeviceInterfaces(hDevInfo, 
                                  0, 
                                  &GUID_DEVINTERFACE_QUANTIS_PCI,
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
  _privateData = (QuantisPrivateData*)malloc(sizeof(QuantisPrivateData));
  if (!_privateData)
  {
    return QUANTIS_ERROR_NO_MEMORY;
  }

  /* Obtain a file handle for the device */
  _privateData->deviceHandle = CreateFile(detailData->DevicePath, 
                                          GENERIC_READ | GENERIC_WRITE, 
                                          0, 
                                          NULL,
                                          OPEN_EXISTING, 
                                          0, 
                                          NULL);

  if (_privateData->deviceHandle == INVALID_HANDLE_VALUE)
  {
    free(_privateData);
    return QUANTIS_ERROR_IO;
  }

  deviceHandle->privateData = _privateData;

  return QUANTIS_SUCCESS;
}



/* Read */
int QuantisPciRead(QuantisDeviceHandle* deviceHandle, void* buffer, size_t size)
{
  DWORD readBytes = 0;
  QuantisPrivateData* _privateData = NULL;  
  BOOL result;

  /* check if at least one module is present/enabled */
  if (QuantisPciGetModulesStatus(deviceHandle) <= 0)
  {
    return QUANTIS_ERROR_NO_MODULE;
  }

  _privateData = (QuantisPrivateData*)deviceHandle->privateData;
  
  result = ReadFile(_privateData->deviceHandle,
                    buffer,
                    (DWORD)size,
                    &readBytes,
                    NULL);

  if (!result || (readBytes != (DWORD)size))
  {
    return QUANTIS_ERROR_IO;
  }

  return (int)readBytes;
}


/* GetBusDeviceId */
int QuantisPciGetBusDeviceId(QuantisDeviceHandle* deviceHandle)
{
  //only implemented with Unix PCI
  return 0;
}

#endif /* DISABLE_QUANTIS_PCI */
