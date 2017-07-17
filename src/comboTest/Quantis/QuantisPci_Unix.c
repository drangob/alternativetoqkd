/*
 * Quantis PCI Library for Unix systems
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

#include "QuantisLibConfig.h"

#ifndef DISABLE_QUANTIS_PCI

#if !(defined(unix) || defined(__unix) || defined(__unix__))
# error "This module is for Unix only!"
#endif

#include <errno.h> 
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "Quantis.h"
#include "Quantis_Internal.h"

#include "Drivers/Unix/QuantisPci/common/quantis_pci.h"

/**
 * QuantisPrivateData for Quantis PCI on Unix systems
 */
typedef struct QuantisPrivateData
{
  int fd; /* File descriptor */
} QuantisPrivateData;


static int QuantisPciIoCtl(QuantisDeviceHandle* deviceHandle, int request, void* arg)
{
  QuantisPrivateData* _privateData = (QuantisPrivateData*)deviceHandle->privateData;
  int result = ioctl(_privateData->fd, request, arg);
  if (result < 0)
  {
    return QUANTIS_ERROR_IO;
  }
  else
  {
    return QUANTIS_SUCCESS;
  }
}


/* Board reset */
int QuantisPciBoardReset(QuantisDeviceHandle* deviceHandle)
{
  return QuantisPciIoCtl(deviceHandle, QUANTIS_IOCTL_RESET_BOARD, NULL);
}


/* Close */
void QuantisPciClose(QuantisDeviceHandle* deviceHandle)
{
  QuantisPrivateData* _privateData = (QuantisPrivateData*)deviceHandle->privateData;

  if (!_privateData)
  {
    return;
  }

  close(_privateData->fd);

  free(_privateData);
  _privateData = NULL;
}


/* Count */
int QuantisPciCount()
{
  int result;
  int deviceNumber = 0;
  int devicesCount = 0;
  QuantisDeviceHandle* deviceHandle = NULL;

  /* Open device */
  result = QuantisOpen(QUANTIS_DEVICE_PCI, deviceNumber, &deviceHandle);
  if (result < 0)
  {
    /* Assumes there is no card installed */
    return 0;
  }

  /* Perform request */
  result = QuantisPciIoCtl(deviceHandle,
                           (int)QUANTIS_IOCTL_GET_CARD_COUNT,
                           &devicesCount);
  if (result < 0)
  {
    /* Assumes there is no card installed */
    devicesCount = 0; 
  }

  /* Close device */
  QuantisClose(deviceHandle);

  return devicesCount;
}


/* GetBoardVersion */
int QuantisPciGetBoardVersion(QuantisDeviceHandle* deviceHandle)
{
  int boardVersion;
  int result;

  result = QuantisPciIoCtl(deviceHandle,
                           (int)QUANTIS_IOCTL_GET_BOARD_VERSION,
                           &boardVersion);
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
  result = QuantisOpen(QUANTIS_DEVICE_PCI, deviceNumber, &deviceHandle);
  if (result < 0)
  {
    /* Assumes there is no card installed */
    return 0.0f;
  }

  /* Perform request */
  result = QuantisPciIoCtl(deviceHandle,
                           (int)QUANTIS_IOCTL_GET_DRIVER_VERSION,
                           &driverVersion);
  if (result < 0)
  {
    /* Assumes there is no card installed */
    driverVersion = 0.0f;
  }

  /* Close device */
  QuantisClose(deviceHandle);

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
                           (int)QUANTIS_IOCTL_GET_MODULES_MASK,
                           &modulesMask);
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
                           (int)QUANTIS_IOCTL_GET_MODULES_STATUS,
                           &modulesStatus);
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
  int params[] = { moduleMask };

  return QuantisPciIoCtl(deviceHandle,
                         QUANTIS_IOCTL_DISABLE_MODULE,
                         &params);
}


/* ModulesEnable */
int QuantisPciModulesEnable(QuantisDeviceHandle* deviceHandle, int moduleMask)
{
  int params[] = { moduleMask };

  return QuantisPciIoCtl(deviceHandle,
                         QUANTIS_IOCTL_ENABLE_MODULE,
                         &params);
}


/* Open */
int QuantisPciOpen(QuantisDeviceHandle* deviceHandle)
{
  char filename[255];
  int fd;

  /* Open device */
  sprintf(filename, "/dev/%s%d", QUANTIS_PCI_DEVICE_NAME, deviceHandle->deviceNumber);

  fd = open(filename, O_RDONLY);
  if (fd < 0)
  {
    return QUANTIS_ERROR_NO_DEVICE;
  }

  /* Allocate memory for private data */
  QuantisPrivateData* _privateData = (QuantisPrivateData*)malloc(sizeof(QuantisPrivateData));
  if (!_privateData)
  {
    return QUANTIS_ERROR_NO_MEMORY;
  }

  /* Copy data */
  _privateData->fd = fd;

  deviceHandle->privateData = _privateData;

  return QUANTIS_SUCCESS;
}


/* Read */
int QuantisPciRead(QuantisDeviceHandle* deviceHandle, void* buffer, size_t size)
{
  /* Check if at least one module is present/enabled */
  if (QuantisPciGetModulesStatus(deviceHandle) <= 0)
  {
    return QUANTIS_ERROR_NO_MODULE;
  }

  /*
   * FreeBSD driver always reads as many bytes as we tell him. Linux and Solaris however
   * writes at most as many bytes as he holds in the device's buffer, thus
   * several reads are necessary.
   */
  size_t readBytes = 0u;
  int result = QUANTIS_ERROR_IO;
  QuantisPrivateData* _privateData = (QuantisPrivateData*)deviceHandle->privateData;
  while (readBytes < size)
  {
    result = read(_privateData->fd,
                  (unsigned char*)buffer + readBytes,
                  size - readBytes);
    if (result < 0)
    {
      if (errno == EINTR)
      {
        /* Read have been interrupted, try again...*/
        continue;
      }
      else
      {
        return QUANTIS_ERROR_IO;
      }
    }

    readBytes += result;
  }

  return result;
}



/* GetBusDeviceId */
int QuantisPciGetBusDeviceId(QuantisDeviceHandle* deviceHandle)
{
  int deviceId;
  int result;

  result = QuantisPciIoCtl(deviceHandle,
                           (int)QUANTIS_IOCTL_GET_PCI_BUS_DEVICE_ID,
                           &deviceId);
  if (result < 0)
  {
    return result;
  }
  else
  {
    return deviceId;
  }
}


#else
int unused;  /* Silence `ISO C forbids an empty translation unit' warning.  */ 
#endif /* DISABLE_QUANTIS_PCI */
