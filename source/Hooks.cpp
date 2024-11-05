#include "Hooks.h"

#include <stacktrace>

namespace Tools
{
	static void DumpStack()
	{
		const auto trace = std::stacktrace::current();
		const auto frames = trace.size();
		const auto start = (frames > 10) ? frames - 10 : 0;

		for (std::size_t i = start; i < frames; ++i) {
			INFO("DumpStack @ Return address: <{}>", trace[i]);
		}
	}
}

namespace Hooks
{
	struct BindObject
	{
		static void Call(RE::BSScript::IVMObjectBindInterface* a_interface, RE::BSTSmartPointer<RE::BSScript::Object>& a_object, RE::VMHandle a_handle, bool a_conditional)
		{
			Callback(a_interface, a_object, a_handle, a_conditional);

			const auto VM = reinterpret_cast<RE::BSScript::Internal::VirtualMachine*>(reinterpret_cast<std::uintptr_t>(a_interface) - 0x10);
			const auto handle_policy = VM->GetObjectHandlePolicy();

			const auto object = a_object ? a_object.get() : nullptr;

			if (!object || a_handle == 0xFFFF00000000) { return; }

			const auto type_info = object->GetTypeInfo();

			if (std::strcmp(type_info->GetName(), "dunSaarthalStaffJyrikSCRIPT")) { return; }

			INFO("");
			INFO("");
			INFO("");
			INFO("BindObject @ Object type info name: <{}>", type_info->GetName());

			const auto form_id = static_cast<RE::FormID>(a_handle);
			const auto form = RE::TESForm::LookupByID(form_id);

			if (form) {
				INFO("BindObject @ FormID: <0x{:X}> | Type: <{}>", form_id, RE::FormTypeToString(form->GetFormType()).data());
			}

			INFO("BindObject @ Handle: <{:X}>", a_handle);

			auto parent = a_handle;

			while (handle_policy->HasParent(parent)) {
				parent = handle_policy->GetParentHandle(parent);

				if (parent == 0xFFFF00000000) { continue; }

				INFO("BindObject @ Parent Handle: <{:X}>", parent);

				const auto parent_form_id = static_cast<RE::FormID>(parent);
				const auto parent_form = RE::TESForm::LookupByID(parent_form_id);

				if (form) {
					INFO("BindObject @ Parent FormID: <0x{:X}> | Type: <{}>", parent_form_id, RE::FormTypeToString(parent_form->GetFormType()).data());
				}
			}

			INFO("");
			INFO("BindObject @ START OF THE CALL STACK:");
			INFO("");

			Tools::DumpStack();

			INFO("");
			INFO("BindObject @ END OF THE CALL STACK");
		}
		static inline REL::Relocation<decltype(Call)> Callback;
	};

	void Install()
	{
		REL::Relocation VTABLE{ RE::BSScript::Internal::VirtualMachine::VTABLE[0], 0x1C0 };
		BindObject::Callback = VTABLE.write_vfunc(0x3, BindObject::Call);

		INFO("Hooked <{}>", typeid(BindObject).name());
	}
}