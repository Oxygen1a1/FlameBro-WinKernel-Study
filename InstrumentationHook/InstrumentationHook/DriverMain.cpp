#include <ntifs.h>
#include <ntddk.h>




//ͨ���������������KProcess.InstrumentationCallBack
//    ProcessInstrumentationCallback               = 40, ʹ�����
//�Ӷ����ǿ�����API��� ����ƫ��׷��
extern "C"
NTSYSAPI
NTSTATUS
NTAPI
ZwSetInformationProcess(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__in_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength
);




NTSTATUS SetProcessCallBack(HANDLE ProcessId, ULONG_PTR InstrumentationCallBack);
ULONG GetPreviousModeOffset();

void DriverUnload(PDRIVER_OBJECT DriverObject);

extern "C" NTSTATUS  DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING pRegPath) {

	UNREFERENCED_PARAMETER(pRegPath);

	//������ д��ShellCode


	
	
	DriverObject->DriverUnload = DriverUnload;

	PEPROCESS Process = 0;
	KAPC_STATE Apc = { 0 };
	HANDLE ProcessId = (HANDLE)9440;
	NTSTATUS status = STATUS_SUCCESS;

	status = PsLookupProcessByProcessId(ProcessId, &Process);

	if (!NT_SUCCESS(status)) {


		DbgPrintEx(77, 0, "unable to get process\r\n");


		return status;
	}

	KeStackAttachProcess(Process, &Apc);

	PVOID baseAddr = NULL;
	SIZE_T size = PAGE_SIZE;

	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &baseAddr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!NT_SUCCESS(status)) {


		DbgPrintEx(77, 0, "unable to alloc mem\r\n");

		KeUnstackDetachProcess(&Apc);

		return status;

	}

	memset(baseAddr, 0, PAGE_SIZE);

	
#pragma warning(disable : 4838)
#pragma warning(disable : 4309)

	char bufcode[] =
	{
		0x51, //push  rcx   
		0x52, //push  rdx
		0x53, //push  rbx												//
		0x55, 															//
		0x56, 															//
		0x57, 															//
		0x41, 0x50, 													//
		0x41, 0x51, 													//
		0x41, 0x52, 													//
		0x41, 0x53, 													//
		0x41, 0x54, 													//
		0x41, 0x55, 													//
		0x41, 0x56, 													//
		0x41, 0x57, 													//
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    //ҪHook�ĵ�ַ
		0x49, 0x39, 0xCA,             //Cmp r10,rcx  �����syscall�ķ��ص�ַ
		//0xB9, 0, 0x00, 0x00, 0,    //mov ecx,c0000
		//0x0F, 0x44, 0xC1,            //cmove eax,ecx.
		0x41, 0x5F,
		0x41, 0x5E,
		0x41, 0x5D,
		0x41, 0x5C,
		0x41, 0x5B,
		0x41, 0x5A,
		0x41, 0x59,
		0x41, 0x58,
		0x5F,
		0x5E,
		0x5D,
		0x5B,
		0x5A,
		0x59,
		0x41, 0xFF, 0xE2  //jmp r10 ����
	};

	//�޸������ַ Ҳ���Ƿ��ص�ַ ��ntdll��OpenProcess ����ֱ�Ӳ���
	*(PULONG64)&bufcode[24] = 0x07FFDA7B8D644;


	memcpy(baseAddr, bufcode, sizeof(bufcode));


	KeUnstackDetachProcess(&Apc);


	status = SetProcessCallBack(ProcessId, (ULONG_PTR)baseAddr);

	if (!NT_SUCCESS(status)) {

		DbgPrintEx(77, 0, "unable to insert callback\r\n");
	
		return status;
	}



	return STATUS_SUCCESS;



}

void DriverUnload(PDRIVER_OBJECT DriverObject) {


	UNREFERENCED_PARAMETER(DriverObject);

}

NTSTATUS SetProcessCallBack(HANDLE ProcessId, ULONG_PTR InstrumentationCallBack) {
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS Process = 0;
	KAPC_STATE Apc = { 0 };
	PACCESS_TOKEN token = { 0 };
	PULONG tokenMask = 0;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) {

		DbgPrintEx(77, 0, "[ProcessCallBack]:unable to get process!\r\n");

		return STATUS_UNSUCCESSFUL;

	}

	if (PsGetProcessExitStatus(Process) != STATUS_PENDING) {


		return STATUS_PROCESS_IS_TERMINATING;
	}

	//��������ʹ�þ����
	KeStackAttachProcess(Process, &Apc);

	//��ȡ����Token������DEBUGȨ��

	token = PsReferencePrimaryToken(Process);

	//����DebugȨ�� ��3��Ȩ�޶����� ��Ϊ����Ȩ��Ϊ3��ULONG����
	//�ֱ������Ȩ�� ������ �Լ�Ĭ�ϵ�
	tokenMask = (PULONG)((ULONG_PTR)token + 0x40);
	//21λ��DEBUGȨ��(λ20)
	tokenMask[0] |= 0x100000;
	tokenMask[1] |= 0x100000;
	tokenMask[2] |= 0x100000;

	//����Instrumentaion
	//���� ע�� Ҫ����ǰģʽ,��Ϊ&InstrumentationCallBack���ܵ�ַУ�鲻��ȥ

	ULONG64 uOffset=GetPreviousModeOffset();
	DbgPrintEx(77, 0, "PreviousModeOffset==0x%x", uOffset);


	status= ZwSetInformationProcess(NtCurrentProcess(), ProcessInstrumentationCallback, &InstrumentationCallBack, 8);

	if (!NT_SUCCESS(status)) {

		KeUnstackDetachProcess(&Apc);

		return status;
	}


	KeUnstackDetachProcess(&Apc);

	return status;
}

ULONG GetPreviousModeOffset() {

	ULONG uOffset = 0;
	UNICODE_STRING usExGetPreviousMode = { 0 };
	int Count = 0;

	RtlInitUnicodeString(&usExGetPreviousMode, L"ExGetPreviousMode");

	

	PUCHAR fnExGetPreviousMode  = (PUCHAR)MmGetSystemRoutineAddress(&usExGetPreviousMode);

	

	for (;;fnExGetPreviousMode++) {

		if (fnExGetPreviousMode[0] == 0XF0 && fnExGetPreviousMode[1] == 0xb6 && fnExGetPreviousMode[2] == 80) {

			uOffset = *(PULONG)(fnExGetPreviousMode + 3);

			return uOffset;

		}
		Count++;

		if (Count > 0x1000) break;


	}

	return uOffset;

}