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
			INFO("DumpStack @ Callee: <{}>", trace[i]);
		}
	}
}

namespace Hooks
{
	struct BindObject
	{
		static void Call(RE::BSScript::IVMObjectBindInterface* a_interface, RE::BSTSmartPointer<RE::BSScript::Object>& a_object, RE::VMHandle a_handle, bool a_conditional)
		{
			const auto VM = reinterpret_cast<RE::BSScript::Internal::VirtualMachine*>(reinterpret_cast<std::uintptr_t>(a_interface) - 0x10);
			const auto handle_policy = VM->GetObjectHandlePolicy();

			RE::BSFixedString output;
			handle_policy->ConvertHandleToString(a_handle, output);

			INFO("");
			INFO("");
			INFO("");
			INFO("BindObject @ Handle: <{}>", output.c_str());

			const auto object = a_object ? a_object.get() : nullptr;

			if (!object) { return; }

			const auto type_info = object->GetTypeInfo();

			INFO("BindObject @ Object type info name: <{}>", type_info->GetName());
			INFO("");
			INFO("BindObject @ START OF THE CALL STACK:");
			INFO("");

			Tools::DumpStack();

			INFO("");
			INFO("BindObject @ END OF THE CALL STACK");

			Callback(a_interface, a_object, a_handle, a_conditional);
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