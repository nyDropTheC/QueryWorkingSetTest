#include <array>
#include <cstdio>
#include <format>
#include <iostream>
#include <memory>
#include <vector>

#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>

// Just a bit of exercise in WinAPI, I haven't touched it in a while
template<typename T>
T resolve_export_from_module(std::wstring_view dll_name, std::string_view export_name) {
	auto dll_base_address = [&dll_name]() -> uintptr_t {
		const PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;

		for (auto entry = peb->Ldr->InMemoryOrderModuleList.Flink; entry != peb->Ldr->InMemoryOrderModuleList.Blink; entry = entry->Flink) {
			const auto module_data = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			if (std::wstring_view{ module_data->FullDllName.Buffer }.contains(dll_name)) {
				return reinterpret_cast<uintptr_t>(module_data->DllBase);
			}
		}

		return 0u;
	}();

	if (!dll_base_address) {
		return T{};
	}

	auto resolved_export = [dll_base_address, &export_name]() -> uintptr_t {
		const auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(dll_base_address);
		const auto nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(dll_base_address + dos_header->e_lfanew);

		// Given we already know the DLL is good (otherwise, it wouldn't be loaded)
		// there's no point in checking for header validity

		const auto image_exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(dll_base_address + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		const auto export_addr_table = reinterpret_cast<uintptr_t*>(dll_base_address + image_exports->AddressOfFunctions);
		const auto export_names = reinterpret_cast<uintptr_t*>(dll_base_address + image_exports->AddressOfNames);
		const auto export_name_ordinals = reinterpret_cast<uint16_t*>(dll_base_address + image_exports->AddressOfNameOrdinals);

		for (auto i = 0u; i < image_exports->NumberOfNames; i++) {
			const auto name = std::string_view{ reinterpret_cast<char*>(dll_base_address + export_names[i]) };
			if (name == export_name) {
				std::uint16_t ordinal = export_name_ordinals[i];

				return dll_base_address + export_addr_table[ordinal];
			}
		}

		return 0u;
	}();
	

	return reinterpret_cast<T>(resolved_export);
}

// Gets working set info for current process
// Might have issues with multi-threading? Who cares anyway, this is far from prod-grade
std::vector<PSAPI_WORKING_SET_BLOCK> get_working_set_info() {
	// kernel32 is loaded all the time anyway, I don't think we need to worry about it not loading
	const auto query_working_set = resolve_export_from_module<int(__stdcall*)(void*, void*, size_t)>(L"KERNEL32.DLL", "K32QueryWorkingSet");

	constexpr auto base_working_set_size = sizeof(PSAPI_WORKING_SET_INFORMATION);
	constexpr auto added_entry_count = 32u; // Kind of a failsafe

	const auto process_handle = GetCurrentProcess();	

	auto temporary_working_set_info = PSAPI_WORKING_SET_INFORMATION{ 0 };
	
	query_working_set(process_handle, &temporary_working_set_info, base_working_set_size);

	auto buffer = std::vector<char>(size_t{ base_working_set_size + (temporary_working_set_info.NumberOfEntries + added_entry_count) * sizeof(PSAPI_WORKING_SET_BLOCK) }, '\0');
	auto working_set_info = reinterpret_cast<PSAPI_WORKING_SET_INFORMATION*>(buffer.data());

	const auto result = query_working_set(process_handle, working_set_info, buffer.size());

	auto ret = std::vector<PSAPI_WORKING_SET_BLOCK>{};

	for (size_t i = 0u; i < working_set_info->NumberOfEntries; i++) {
		ret.push_back(working_set_info->WorkingSetInfo[i]);
	}

	return ret;
}

int main() {
	const auto vec = get_working_set_info();

	std::array<std::string_view, 32> protection_types = {
		"NA",
		"R",
		"X",
		"RX",
		"RW",
		"CoW",
		"RWX",
		"CoW & X",
		"NA",
		"NC R",
		"NC X",
		"NC RX",
		"NC RW",
		"NC CoW",
		"NC RWX",
		"NC CoW X",
		"NA",
		"G R",
		"G X",
		"G RX",
		"G RW",
		"G CoW",
		"G RWX",
		"G CoW X",
		"NA",
		"NC G R",
		"NC G X",
		"NC G RX",
		"NC G RW",
		"NC G CoW",
		"NC G RWX",
		"NC G CoW X"
	};

	for (const auto memory_entry : vec) {
		std::printf("Page 0x%x\n", memory_entry.VirtualPage * 0x1000);
		std::printf("Share count: %d, shared: %d\n", memory_entry.ShareCount, memory_entry.Shared);
		std::printf("Protection: %s [%d]\n", protection_types.at(memory_entry.Protection).data(), memory_entry.Protection);
	}
}