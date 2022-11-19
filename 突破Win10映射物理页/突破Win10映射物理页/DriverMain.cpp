#include <ntifs.h>
#include <ntddk.h>


void UnloadDriver(PDRIVER_OBJECT Driver);

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT Driver,PUNICODE_STRING pRegPath) {

	UNREFERENCED_PARAMETER(pRegPath);
	

	PHYSICAL_ADDRESS Cr3 = { 0 };

	Cr3.QuadPart = 0x9b632000;

	//使用这个函数映射


	//win7可以成功 但是win10是不成功的
	//Spte 页表相关的物理内存不能映射(其余的可以)
	//其实微软是有一个口子的 可以突破
	//PhysicalMemory就是描述 物理设备的
	//但是他是节区对象 打开这个节区对象
	// 其实节区对象就是代表一块物理内存
	//然后调用ZwMapViewOfSection来映射

	//PVOID pMapByPhyical = MmMapIoSpace(Cr3, PAGE_SIZE, MmNonCached);

	//KdPrint(("映射的地址:0x%p\r\n",pMapByPhyical));
	//映射到0环地址就直接用MmMapViewInSystemSpace映射到内核

	Driver->DriverUnload = UnloadDriver;


	HANDLE hMemory = NULL;
	UNICODE_STRING unName = { 0 };
	RtlInitUnicodeString(&unName, L"\\Device\\PhysicalMemory");
	DbgBreakPoint();
	OBJECT_ATTRIBUTES obj;
	InitializeObjectAttributes(&obj, &unName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS status = ZwOpenSection(&hMemory, SECTION_ALL_ACCESS, &obj);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	PVOID base = NULL;
	SIZE_T sizeView = PAGE_SIZE;
	LARGE_INTEGER lage = { 0 };
	lage.QuadPart = 0x9b532000;

	PVOID sectionObj = NULL;
	status = ObReferenceObjectByHandle(hMemory, SECTION_ALL_ACCESS, NULL, KernelMode, &sectionObj, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	
	//其中第6个就是一个偏移
	//是Section所描述的物理地址的偏移
	//为什么这样说呢?因为PhysicalMemory这个Section对象描述的是从0开始到本机实际物理地址的所有偏移


	status = ZwMapViewOfSection(hMemory,
		NtCurrentProcess(), &base,
		0, PAGE_SIZE, &lage, &sizeView, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);


	//ZwUnmapViewOfSection(NtCurrentProcess(), base);

	int count = 0;

	for (int i = 0; i < 512; i++) {

		


		if (count == 8) {
			DbgPrintEx(77, 0, "\r\n");
			count = 0;
		}

		DbgPrintEx(77,0,"Pml4e Traverse:0x%p  ",((PUINT64)base)[i]);
		count++;

	}

	ZwClose(hMemory);

	return STATUS_SUCCESS;
}

void UnloadDriver(PDRIVER_OBJECT Driver) {
	UNREFERENCED_PARAMETER(Driver);


}