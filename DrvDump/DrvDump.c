#include <ntifs.h>
#include <ntddk.h>
#include <Ntstrsafe.h>

#define DRVMON_DEVICE_NT_NAME		L"\\Device\\DrvDump"
#define DRVMON_WIN32_DEVICE_NAME	L"\\DosDevices\\DrvDump"
#define	DRVMON_DUMP_DIRECTORY		L"\\??\\C:\\stuff\\"		// must be present!


NTSTATUS 
DriverEntry(
	__in PDRIVER_OBJECT DriverObject,
	__in PUNICODE_STRING RegistryPath
	);

DRIVER_UNLOAD DrvDumpDriverUnload;
VOID DrvDumpDriverUnload(__in PDRIVER_OBJECT DriverObject);

__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH DrvDumpDispatchOpen;
NTSTATUS DrvDumpDispatchOpen(
	__in PDEVICE_OBJECT pDO,
	__in PIRP Irp);

__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH DrvDumpDispatchClose;
NTSTATUS DrvDumpDispatchClose(
	__in PDEVICE_OBJECT pDO,
	__in PIRP Irp);

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DrvDumpDispatchDeviceControl;
NTSTATUS DrvDumpDispatchDeviceControl(
	__in PDEVICE_OBJECT pDO,
	__in PIRP Irp);

VOID
LoadImageCallback(
	__in_opt PUNICODE_STRING  FullImageName,
	__in HANDLE hProcessId,
	__in PIMAGE_INFO ImageInfo);

VOID 
DumpDriver(__in PUNICODE_STRING FullImageName);

LPWSTR
GenerateFileName(__in PUNICODE_STRING DriverName);

ULONG DumpIndex = 1;


NTSTATUS
DriverEntry(
	__in PDRIVER_OBJECT DriverObject,
	__in PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	UNICODE_STRING DeviceName, DeviceLinkName;
	PDEVICE_OBJECT pDrvDumpDeviceObject;

	DriverObject->DriverUnload = DrvDumpDriverUnload;
	DriverObject->MajorFunction[ IRP_MJ_CREATE ] = DrvDumpDispatchOpen;
	DriverObject->MajorFunction[ IRP_MJ_CLOSE ] = DrvDumpDispatchClose;
	DriverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = DrvDumpDispatchDeviceControl;

	RtlInitUnicodeString(&DeviceName, DRVMON_DEVICE_NT_NAME);
	
	status = IoCreateDevice(DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&pDrvDumpDeviceObject);

	if(!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDrvDumpDeviceObject);
		return status;
	}

	RtlInitUnicodeString(&DeviceLinkName, DRVMON_WIN32_DEVICE_NAME);
	status = IoCreateSymbolicLink(&DeviceLinkName, &DeviceName);

	if(!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDrvDumpDeviceObject);
		return status;
	}

	pDrvDumpDeviceObject->Flags |= DO_BUFFERED_IO;
	
	PsSetLoadImageNotifyRoutine(LoadImageCallback);

	DbgPrint("[*] DrvDump loaded succesfully\n");
	return	STATUS_SUCCESS;
}

		
NTSTATUS 
DrvDumpDispatchDeviceControl(
	__in PDEVICE_OBJECT pDO, 
	__in PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack =  IoGetCurrentIrpStackLocation(Irp);

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS
DrvDumpDispatchOpen(
	__in PDEVICE_OBJECT pDO,
	__in PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	
	return STATUS_SUCCESS;
}

NTSTATUS
DrvDumpDispatchClose(
	__in PDEVICE_OBJECT pDO,
	__in PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	
	return STATUS_SUCCESS;
}

VOID
DrvDumpDriverUnload(__in PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING DeviceLinkName;

	DbgPrint("[*] DrvDump Unloading\n");

	PsRemoveLoadImageNotifyRoutine(LoadImageCallback);

	RtlInitUnicodeString(&DeviceLinkName, DRVMON_WIN32_DEVICE_NAME);
	IoDeleteSymbolicLink(&DeviceLinkName);

	IoDeleteDevice(DriverObject->DeviceObject);
}



VOID
LoadImageCallback(
	__in_opt PUNICODE_STRING  FullImageName,
	__in HANDLE hProcessId,
	__in PIMAGE_INFO ImageInfo)
{
	if(hProcessId) // not a driver image
		return;

	if(FullImageName && FullImageName->Length)
		DumpDriver(FullImageName);
}


VOID 
DumpDriver(__in PUNICODE_STRING FullImageName)
{
	NTSTATUS status;
	ULONG FileSize = 0;
	OBJECT_ATTRIBUTES ObjAttr = {0};
	IO_STATUS_BLOCK IoStatus = {0};
	FILE_STANDARD_INFORMATION FileInfo = {0};
	HANDLE SrcFileHandle, DstFileHandle;
	UNICODE_STRING DumpName = {0};
	PVOID Buffer;

	ObjAttr.Length = sizeof(OBJECT_ATTRIBUTES);
	ObjAttr.Attributes = OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE;
	ObjAttr.ObjectName = FullImageName;


	status = NtOpenFile(&SrcFileHandle,
		FILE_READ_DATA,
		&ObjAttr,
		&IoStatus,
		FILE_SHARE_VALID_FLAGS,
		FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE);
	if(!NT_SUCCESS(status))
	{
		DbgPrint("[!!] Cannot NtOpenFile %wZ, NtStatus: %08x\n", FullImageName, status);
		return;
	}

	status = NtQueryInformationFile(SrcFileHandle,
		&IoStatus,
		&FileInfo,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
	if(!NT_SUCCESS(status))
	{
		DbgPrint("[!!] Cannot NtQueryInformationFile %wZ, NtStatus: %08x\n", FullImageName, status);
		NtClose(SrcFileHandle);
		return;
	}

	FileSize = FileInfo.EndOfFile.LowPart ? FileInfo.EndOfFile.LowPart : FileInfo.AllocationSize.LowPart;
	if(!FileSize)
	{
		DbgPrint("[!!] Got zero file size for %wZ, NtStatus: %08x\n", FullImageName, status);
		NtClose(SrcFileHandle);
		return;
	}



	memset(&ObjAttr, 0x0, sizeof(OBJECT_ATTRIBUTES));
	ObjAttr.Length = sizeof(OBJECT_ATTRIBUTES);
	ObjAttr.Attributes = OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE;
	RtlInitUnicodeString(&DumpName, GenerateFileName(FullImageName));
	ObjAttr.ObjectName = &DumpName;

	DbgPrint("Dumping %wZ\n", &DumpName);
	status = NtCreateFile(&DstFileHandle, 
		GENERIC_WRITE,
		&ObjAttr,
		&IoStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_SUPERSEDE,
		FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,
		NULL,
		0);

	if(!NT_SUCCESS(status))
	{
		DbgPrint("[!!] Cannot NtCreateFile %wZ, NtStatus: %08x\n", ObjAttr.ObjectName, status);
		NtClose(SrcFileHandle);
		ExFreePoolWithTag(DumpName.Buffer, 'w00t');

		return;
	}

	Buffer = ExAllocatePoolWithTag(NonPagedPool, FileSize, 'w00t');
	RtlZeroMemory(Buffer, FileSize);
	status = NtReadFile(SrcFileHandle,
		NULL,
		NULL,
		NULL,
		&IoStatus,
		Buffer,
		FileSize,
		0,
		0);

	if(!NT_SUCCESS(status))
	{
		DbgPrint("[!!] Cannot NtReadFile %wZ, NtStatus: %08x\n", ObjAttr.ObjectName, status);
		ExFreePoolWithTag(Buffer, 'w00t');	
		ExFreePoolWithTag(DumpName.Buffer, 'w00t');
		NtClose(SrcFileHandle);
		NtClose(DstFileHandle);
		return;
	}

	status = NtWriteFile(DstFileHandle,
		NULL,
		NULL,
		NULL,
		&IoStatus,
		Buffer,
		FileSize,
		0,
		0);

	if(!NT_SUCCESS(status))
		DbgPrint("[!!] Cannot NtWriteFile %wZ, NtStatus: %08x\n", ObjAttr.ObjectName, status);
	

	ExFreePoolWithTag(Buffer, 'w00t');	
	ExFreePoolWithTag(DumpName.Buffer, 'w00t');
	NtClose(SrcFileHandle);
	NtClose(DstFileHandle);
}

LPWSTR 
GenerateFileName(__in PUNICODE_STRING DriverName)
{
	PUCHAR StringBuffer;
	LPWSTR FileName, FileIdx;
	ULONG i, idx;

	FileName = ExAllocatePoolWithTag(NonPagedPool, 4096, 'w00t');
	FileIdx = ExAllocatePoolWithTag(NonPagedPool, 4096, 'w00t');
	StringBuffer = (PUCHAR)DriverName->Buffer;
	RtlZeroMemory(FileName, 4096);

	idx = 0;
	for(i=0; i<((ULONG)DriverName->Length); i=i+2)
	{
		if(StringBuffer[i] == 0 && StringBuffer[i+1] == 0)
			break;
		
		if(StringBuffer[i] == 0x5c && StringBuffer[i+1] == 0)
			idx = i;
	}
	RtlStringCchPrintfW(FileIdx, 17, L".%d", DumpIndex++);
	RtlStringCchCatW(FileName, 4096, DRVMON_DUMP_DIRECTORY);
	RtlStringCchCatW(FileName, 4096, (LPWSTR)&StringBuffer[idx+2]);
	RtlStringCchCatW(FileName, 4096, FileIdx);

	ExFreePoolWithTag(FileIdx, 'w00t');

	return FileName;
}

