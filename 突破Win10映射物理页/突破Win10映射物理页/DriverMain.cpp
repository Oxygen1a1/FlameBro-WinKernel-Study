#include <ntifs.h>
#include <ntddk.h>


void UnloadDriver(PDRIVER_OBJECT Driver);

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT Driver,PUNICODE_STRING pRegPath) {

	UNREFERENCED_PARAMETER(pRegPath);
	

	PHYSICAL_ADDRESS Cr3 = { 0 };

	Cr3.QuadPart = 0x9b632000;

	//ʹ���������ӳ��


	//win7���Գɹ� ����win10�ǲ��ɹ���
	//Spte ҳ����ص������ڴ治��ӳ��(����Ŀ���)
	//��ʵ΢������һ�����ӵ� ����ͻ��
	//PhysicalMemory�������� �����豸��
	//�������ǽ������� �������������
	// ��ʵ����������Ǵ���һ�������ڴ�
	//Ȼ�����ZwMapViewOfSection��ӳ��

	//PVOID pMapByPhyical = MmMapIoSpace(Cr3, PAGE_SIZE, MmNonCached);

	//KdPrint(("ӳ��ĵ�ַ:0x%p\r\n",pMapByPhyical));
	//ӳ�䵽0����ַ��ֱ����MmMapViewInSystemSpaceӳ�䵽�ں�

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

	
	//���е�6������һ��ƫ��
	//��Section�������������ַ��ƫ��
	//Ϊʲô����˵��?��ΪPhysicalMemory���Section�����������Ǵ�0��ʼ������ʵ�������ַ������ƫ��


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