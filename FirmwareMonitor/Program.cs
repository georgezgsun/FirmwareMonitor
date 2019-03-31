using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;

using System.Threading;
using System.Threading.Tasks;

namespace PiCBootLoader
{
    using System;
    using System.IO;
    using System.Collections.Generic;
    using System.Management;
    using Microsoft.Win32;
    using Microsoft.Win32.SafeHandles;
    using System.Runtime.InteropServices;

    public partial class GenericUSBHIDLibrary
    {
        string USBHIDDevicePath = @"\\?\hid#vid_04d8&pid_003c#8&33ed0aab&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}";
        public bool IsFound = false;
        public bool IsConnected = false;
        private const int blockSize = 65;
        string VID;
        string PID;

        SafeFileHandle handleDeviceWrite;
        static object Synch = new object();

        public GenericUSBHIDLibrary(string vid, string pid)
        {
            VID = vid.Length == 4 ? vid.ToLower() : "04d8";
            PID = pid.Length == 4 ? pid.ToLower() : "003c";
            IsFound = false;

            USBHIDDevicePath = GetPICPath();
        }

        ~GenericUSBHIDLibrary()
        {
            CloseFileHandleOfHID();
        }

        public string HIDDeviceConnectionString
        {
            get { return USBHIDDevicePath; }
            set { USBHIDDevicePath = value; }
        }

        public string GetPICPath()
        {
            int listIndex = 0;
            string devicePath;
            IsFound = false;

            Int32 bufferSize = 0;
            IntPtr detailDataBuffer = IntPtr.Zero;
            IntPtr deviceInfoSet = new System.IntPtr();
            SP_DEVICE_INTERFACE_DATA deviceInterfaceData = new SP_DEVICE_INTERFACE_DATA();
            try
            {

                //Get HID group GUID
                System.Guid systemHidGuid = new Guid();
                HidD_GetHidGuid(ref systemHidGuid);

                // Here we populate a list of plugged-in devices matching our class GUID (DIGCF_PRESENT specifies that the list
                deviceInfoSet = SetupDiGetClassDevs(ref systemHidGuid, IntPtr.Zero, IntPtr.Zero, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
                deviceInterfaceData.cbSize = Marshal.SizeOf(deviceInterfaceData);

                // Look through the retrieved list of class GUIDs looking for a match on our interface GUID
                bool lastDevice = false;
                bool success;
                do
                {
                    success = SetupDiEnumDeviceInterfaces(deviceInfoSet, IntPtr.Zero, ref systemHidGuid, listIndex, ref deviceInterfaceData);
                    if (!success)
                    {
                        lastDevice = true;
                    }
                    else
                    {
                        // The target device has been found, now we need to retrieve the device path

                        // First call is just to get the required buffer size for the real request
                        success = SetupDiGetDeviceInterfaceDetail(deviceInfoSet, ref deviceInterfaceData, IntPtr.Zero, 0, ref bufferSize, IntPtr.Zero);
                        // Allocate some memory for the buffer
                        detailDataBuffer = Marshal.AllocHGlobal(bufferSize);
                        Marshal.WriteInt32(detailDataBuffer, (IntPtr.Size == 4) ? (4 + Marshal.SystemDefaultCharSize) : 8);

                        // Second call gets the detailed data buffer
                        success = SetupDiGetDeviceInterfaceDetail(deviceInfoSet, ref deviceInterfaceData, detailDataBuffer, bufferSize, ref bufferSize, IntPtr.Zero);

                        // Skip over cbsize (4 bytes) to get the address of the devicePathName.
                        IntPtr pDevicePathName = new IntPtr(detailDataBuffer.ToInt32() + 4);

                        // Get the String containing the devicePathName.
                        devicePath = Marshal.PtrToStringAuto(pDevicePathName);
                        //Console.WriteLine("Check the HID device with device path of {0}", devicePath);
                        if (devicePath.Contains("vid_" + VID) && devicePath.Contains("pid_" + PID))
                        {
                            //Console.WriteLine("Find the HID device with device path of {0}", devicePath);
                            USBHIDDevicePath = devicePath;
                            IsFound = true;
                            return devicePath;
                        }
                    }

                    listIndex++;
                }
                while (!((lastDevice == true)));
            }
            catch (Exception ex)
            {
                Console.WriteLine("HIDDevice:  Error in GetListDevicePath()" + ex.Message, "Error", 2003);
            }
            finally
            {
                // Clean up the unmanaged memory allocations
                if (detailDataBuffer != IntPtr.Zero)
                {
                    // Free the memory allocated previously by AllocHGlobal.
                    Marshal.FreeHGlobal(detailDataBuffer);
                }

                if (deviceInfoSet != IntPtr.Zero)
                {
                    SetupDiDestroyDeviceInfoList(deviceInfoSet);
                }
            }

            USBHIDDevicePath = "";
            IsFound = false;
            return USBHIDDevicePath;
        }

        #region Read & Write Report to HID

        public bool Connect()
        {
            IsConnected = false;

            if (USBHIDDevicePath.Length <= 0)
            {
                //Console.WriteLine("PIC connect error - USBHIDDevicePath.Length <= 0");
                //log.WriteLine("PIC connect error - USBHIDDevicePath.Length <= 0");
                return false;
            }

            CommTimeouts timeouts = null;
            try
            {
                timeouts = new CommTimeouts
                {
                    ReadIntervalTimeout = 0x10, //milliseconds allowed to elapse between two bytes on the communications line. 
                    ReadTotalTimeoutMultiplier = 0x01, //Multiplier in milliseconds used to calculate the total time-out period for read operations.
                    ReadTotalTimeoutConstant = 0x96, //Constant in milliseconds used to calculate the total time-out period for read operations.
                    WriteTotalTimeoutMultiplier = 0, //A value of zero for both the WriteTotalTimeoutMultiplier and WriteTotalTimeoutConstant members indicates that total time-outs are not used for write operations.
                    WriteTotalTimeoutConstant = 0
                };
                // If there are any bytes in the input buffer, ReadFile returns immediately with the bytes in the buffer.
                // If there are no bytes in the input buffer, ReadFile waits until a byte arrives and then returns immediately.
                // If no bytes arrive within the time specified by ReadTotalTimeoutConstant, ReadFile times out.

                handleDeviceWrite = CreateFile(USBHIDDevicePath, //The USB path of the device to be opened. 
                    GENERIC_WRITE | GENERIC_READ,  //The requested access to the device. Here is both read and write.
                    FILE_SHARE_READ | FILE_SHARE_WRITE, //The requested sharing mode of the device. Here allows both read and write.
                    IntPtr.Zero,
                    OPEN_EXISTING, //An action to take on a that exists. This is usually set to OPEN_EXISTING for devices.
                    0,
                    0);

                if (handleDeviceWrite.IsInvalid)
                {
                    Console.WriteLine("PIC connect error - handleDeviceWrite.IsInvalid");
                    handleDeviceWrite = null;
                    return false;
                }

                SetCommTimeouts(handleDeviceWrite, timeouts);
                IsConnected = true;

                return IsConnected;
            }

            catch (Exception ex)
            {
                string error = ex.Message;

                if (ex.InnerException != null)
                {
                    error += Environment.NewLine + ex.InnerException.Message;
                }

                Console.WriteLine("Connect exception - {0}", error);
            }

            finally
            {
                GC.Collect();
            }

            return false;
        }

        public void CloseFileHandleOfHID()
        {
            try
            {
                if (handleDeviceWrite != null)
                {
                    handleDeviceWrite.Close();
                    handleDeviceWrite.Dispose();
                    handleDeviceWrite = null;
                }
            }

            catch (Exception ex)
            {
                Console.WriteLine("GenericUSBHIDLibrary::CloseFileHandleOfHID exception - " + ex.Message, "Error", 2050);
            }

            finally
            {
            }
        }

        public void ResetFileHandle()
        {
            try
            {
                Console.WriteLine("GenericUSBHIDLibrary - Resetting file handle");

                // Close our current file handle.
                CloseFileHandleOfHID();

                // Attempt to open a fresh handle.
                Connect();
            }

            catch (Exception ex)
            {
                Console.WriteLine("GenericUSBHIDLibrary::ResetFileHandle exception - {0}", ex.Message);
            }

            finally
            {
            }
        }

        public bool WriteReportToHID(Byte[] buffer, int bufLength)
        {
            if (handleDeviceWrite == null)
                Connect();

            if (handleDeviceWrite == null)
            {
                Console.WriteLine("WriteReportToHID failed - null file handle.");
                return false;
            }
            if (handleDeviceWrite.IsInvalid)
            {
                Console.WriteLine("WriteReportToHID failed - invalid (.Invalid) file handle.");
                return false;
            }
            if (handleDeviceWrite.IsClosed)
            {
                Console.WriteLine("WriteReportToHID failed - closed (.IsClosed) file handle.", "Error", 2050);
                return false;
            }
            if (buffer[0] != 0)
            {
                Console.WriteLine("WriteReportToHID failed - buffer[0] has to be 0.", "Error", 2050);
                return false;
            }

            int numberOfBytesWritten = 0;
            bool success;
            int i = 0;

            for (i = bufLength; i < 65; i++)
                buffer[i] = (byte)0xFF;

            try
            {
                success = WriteFile(handleDeviceWrite, buffer, 65, ref numberOfBytesWritten, IntPtr.Zero);
            }
            catch (Exception ex)
            {
                Console.WriteLine("WriteReportToHID - failed [" + Marshal.GetLastWin32Error() + "]", "Error", 2050);
                string error = ex.Message;

                if (ex.InnerException != null)
                    error += Environment.NewLine + ex.InnerException.Message;

                Console.WriteLine("WriteReportToHID exception - {0}", error);

                throw new Exception(ex.Message);
            }
            finally
            {
                GC.Collect();
            }

            return success;
        }

        public bool ReadReportFromHID(Byte[] inputReportBuffer, ref int numberOfBytesRead)
        {
            IntPtr nonManagedBuffer = IntPtr.Zero;
            int result = 0;
            bool success;

            IntPtr eventObject = IntPtr.Zero;
            IntPtr nonManagedOverlapped = IntPtr.Zero;
            NativeOverlapped hidOverlapped = new NativeOverlapped();
            try
            {
                // Allocate memory for the unmanaged input buffer and overlap structure.
                nonManagedBuffer = Marshal.AllocHGlobal(blockSize);
                nonManagedOverlapped = Marshal.AllocHGlobal(Marshal.SizeOf(hidOverlapped));
                Marshal.StructureToPtr(hidOverlapped, nonManagedOverlapped, false);

                numberOfBytesRead = 0;
                success = ReadFile(handleDeviceWrite, nonManagedBuffer, blockSize, ref numberOfBytesRead, IntPtr.Zero); //nonManagedOverlapped);

                if (success)
                    Marshal.Copy(nonManagedBuffer, inputReportBuffer, 0, numberOfBytesRead);
                else
                {
                    result = Marshal.GetLastWin32Error();
                    Console.WriteLine("ReadReportFromHID:  ReadFile failed [" + result + "].");
                }
            }
            catch (Exception ex)
            {
                string error = ex.Message;

                if (ex.InnerException != null)
                    error += Environment.NewLine + ex.InnerException.Message;

                // An error - send out some debug and return failure
                Console.WriteLine("ReadReportFromHID:  Exception getting data: {0}", error);
                throw new Exception(ex.Message);
            }
            finally
            {
                //Release non-managed objects before returning
                Marshal.FreeHGlobal(nonManagedBuffer);
                Marshal.FreeHGlobal(nonManagedOverlapped);

                //Close the file handle to release the object
                CloseHandle(eventObject);
                GC.Collect();
            }

            return success;
        }

        #endregion

        [StructLayout(LayoutKind.Sequential)]
        internal struct HIDD_ATTRIBUTES
        {
            internal Int32 size;
            internal UInt16 vendorId;
            internal UInt16 productId;
            internal UInt16 versionNumber;
        }

        #region HID DLL functions
        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_FlushQueue(SafeFileHandle HidDeviceObject);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_FreePreparsedData(IntPtr PreparsedData);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_GetAttributes(SafeFileHandle HidDeviceObject, ref HIDD_ATTRIBUTES Attributes);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_GetFeature(SafeFileHandle HidDeviceObject, Byte[] lpReportBuffer, Int32 ReportBufferLength);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_GetInputReport(SafeFileHandle HidDeviceObject, Byte[] lpReportBuffer, Int32 ReportBufferLength);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern void HidD_GetHidGuid(ref System.Guid HidGuid);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_GetNumInputBuffers(SafeFileHandle HidDeviceObject, ref Int32 NumberBuffers);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_GetPreparsedData(SafeFileHandle HidDeviceObject, ref IntPtr PreparsedData);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_SetFeature(SafeFileHandle HidDeviceObject, Byte[] lpReportBuffer, Int32 ReportBufferLength);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_SetNumInputBuffers(SafeFileHandle HidDeviceObject, Int32 NumberBuffers);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_SetOutputReport(SafeFileHandle HidDeviceObject, Byte[] lpReportBuffer, Int32 ReportBufferLength);

        //[DllImport("hid.dll", SetLastError = true)]
        //internal static extern Int32 HidP_GetCaps(IntPtr PreparsedData, ref HIDP_CAPS Capabilities);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Int32 HidP_GetValueCaps(Int32 ReportType, Byte[] ValueCaps, ref Int32 ValueCapsLength, IntPtr PreparsedData);
        #endregion

        #region Setup DLL function
        internal const Int32 DIGCF_PRESENT = 2;
        internal const Int32 DIGCF_DEVICEINTERFACE = 0X10;

        internal struct SP_DEVICE_INTERFACE_DATA
        {
            internal Int32 cbSize;
            internal System.Guid InterfaceClassGuid;
            internal Int32 Flags;
            internal IntPtr Reserved;
        }

        [DllImport("setupapi.dll", SetLastError = true)]
        internal static extern Int32 SetupDiCreateDeviceInfoList(ref System.Guid ClassGuid, Int32 hwndParent);

        [DllImport("setupapi.dll", SetLastError = true)]
        internal static extern Int32 SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        [DllImport("setupapi.dll", SetLastError = true)]
        internal static extern Boolean SetupDiEnumDeviceInterfaces(IntPtr DeviceInfoSet, IntPtr DeviceInfoData, ref System.Guid InterfaceClassGuid, Int32 MemberIndex, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern IntPtr SetupDiGetClassDevs(ref System.Guid ClassGuid, IntPtr Enumerator, IntPtr hwndParent, Int32 Flags);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern Boolean SetupDiGetDeviceInterfaceDetail(
            IntPtr DeviceInfoSet,
            ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
            IntPtr DeviceInterfaceDetailData,
            Int32 DeviceInterfaceDetailDataSize,
            ref Int32 RequiredSize,
            IntPtr DeviceInfoData);
        #endregion

        #region Kernel Dll functions
        internal const Int32 FILE_FLAG_OVERLAPPED = 0x40000000;
        internal const Int32 FILE_SHARE_READ = 1;
        internal const Int32 FILE_SHARE_WRITE = 2;
        internal const UInt32 GENERIC_READ = 0x80000000;
        internal const UInt32 GENERIC_WRITE = 0x40000000;
        internal const Int32 INVALID_HANDLE_VALUE = -1;
        internal const Int32 OPEN_EXISTING = 3;
        internal const Int32 TRUNCATE_EXISTING = 5;
        internal const Int32 WAIT_TIMEOUT = 0x102;
        internal const Int32 WAIT_OBJECT_0 = 0;

        [StructLayout(LayoutKind.Sequential)]
        internal class SECURITY_ATTRIBUTES
        {
            internal Int32 nLength;
            internal Int32 lpSecurityDescriptor;
            internal Int32 bInheritHandle;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern Int32 CancelIo(
            SafeFileHandle hFile
            );

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr CreateEvent(
            IntPtr SecurityAttributes,
            Boolean bManualReset,
            Boolean bInitialState,
            String lpName
            );

        // opens files that access usb hid devices
        //[DllImport("kernel32.dll", SetLastError = true)]
        //public static extern IntPtr CreateFile(
        //    [MarshalAs(UnmanagedType.LPStr)] string strName,
        //    uint nAccess, 
        //    uint nShareMode, 
        //    IntPtr lpSecurity,
        //    uint nCreationFlags, 
        //    uint nAttributes, 
        //    IntPtr lpTemplate);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern SafeFileHandle CreateFile(
            String lpFileName,
            UInt32 dwDesiredAccess,
            Int32 dwShareMode,
            IntPtr lpSecurityAttributes,
            Int32 dwCreationDisposition,
            Int32 dwFlagsAndAttributes,
            Int32 hTemplateFile
            );

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern Boolean GetOverlappedResult(
            SafeFileHandle hFile,
            IntPtr lpOverlapped,
            ref Int32 lpNumberOfBytesTransferred,
            Boolean bWait
            );

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern Boolean ReadFile(
            SafeFileHandle hFile,
            IntPtr lpBuffer,
            Int32 nNumberOfBytesToRead,
            ref Int32 lpNumberOfBytesRead,
            IntPtr lpOverlapped
            );

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern Int32 WaitForSingleObject(
            IntPtr hHandle,
            Int32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern Int32 SetCommTimeouts(
            SafeFileHandle hFile,
            CommTimeouts timeouts);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern Boolean FlushFileBuffers(
            SafeFileHandle hFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern Boolean WriteFile(
            SafeFileHandle hFile,
            Byte[] lpBuffer,
            Int32 nNumberOfBytesToWrite,
            ref Int32 lpNumberOfBytesWritten,
            IntPtr lpOverlapped
            );

        [DllImport("kernel32", SetLastError = true)]
        internal static extern bool CloseHandle(
            IntPtr h
            );

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();
        #endregion
    }

    internal class CommTimeouts
    {
        public UInt32 ReadIntervalTimeout;
        public UInt32 ReadTotalTimeoutMultiplier;
        public UInt32 ReadTotalTimeoutConstant;
        public UInt32 WriteTotalTimeoutMultiplier;
        public UInt32 WriteTotalTimeoutConstant;
    }

    class Program
    {
        static StreamWriter log;

        static void Main(string[] args)
        {
            byte[] buf = new byte[65];

            string logfilename = "TriggerMonitor.log";
            string report;
            string[] newArgs;
            string monitor = "trigger";
            string display = "onchanged";

            if (args.Length == 0)
            {
                report = "log=TriggerMonitor.log monitor=noGPS display=onchanged";
                Console.WriteLine();
                Console.WriteLine("Firmware Monitor");
                Console.WriteLine(" -Current arguments are " + report);
                Console.WriteLine(" Arguments: [log=[filename]] [monitor=[all, triggerOnly, noGPS]] [display=[all, onChanged]], when monitor is equals to all or noGPS, CopTrax App or Validation tool need to be run");
                Console.Write("Press Enter to confirm or enter new arguments : ");

                string line = Console.ReadLine();
                if (line.Length == 0)
                    line = report;
                newArgs = line.Split(new char[] { ' ' });
            }
            else
                newArgs = args;

            for (int i = 0; i < newArgs.Length; i++)
            {
                string[] splt = newArgs[i].Split(new char[] { '=' });
                if (newArgs[i].Contains("log=") && splt.Length == 2)
                    logfilename = splt[1];
                if (newArgs[i].Contains("monitor=") && splt.Length == 2)
                    monitor = splt[1].ToLower();
                if (newArgs[i].Contains("display=") && splt.Length == 2)
                    display = splt[1].ToLower();
            }

            log = new StreamWriter(logfilename, true);
            Console.WriteLine("Trigger monitor 1.0");
            log.WriteLine("Trigger monitor 1.0");
            report = "Firmware Monitor, log=" + logfilename + ", monitor=" + monitor + ", display=" + display;
            Console.WriteLine(report);
            log.WriteLine(report);

            GenericUSBHIDLibrary pic = new GenericUSBHIDLibrary("04d8", "F2BF"); //VID=04D8, PID=003C for boot loader mode, PID=F2BF for firmware mode
            if (!pic.IsFound)
            {
                report = "Cannot find any PIC devices.";
                Console.WriteLine(report);
                log.WriteLine(report);

                Console.ReadLine();
                return;
            }

            Console.WriteLine("Found {0} in firmware mode.", pic.HIDDeviceConnectionString);
            log.WriteLine("Found {0} in firmware mode.", pic.HIDDeviceConnectionString);

            report = "The triggers are Pin4-Pin3-Pin6-Pin5 NUL-NUL-LSB-SRN MIC2-MIC1-EMG-RFI LP-CHG-AUX4-HIV TMP-PUR-IMP-IGN STATUS";
            Console.WriteLine(report);
            log.WriteLine(report);
            report = "The GPS are (Latitude, Longtitude, Altitude), (GEOID_Altitude), (Speed), (hh:mm:ss), (mm/dd/yy)";
            Console.WriteLine(report);
            log.WriteLine(report);
            log.Flush();

            if (pic.Connect())
            {
                bool ret;
                int len = 0;
                string report0 = "";
                string cmd = "";
                DateTime now;

                while (true)
                {
                    len = 0;
                    buf[len++] = 0;
                    buf[len++] = 0xB2;
                    buf[len++] = 0x03;
                    buf[len++] = 0x24;
                    buf[len++] = 0x27;
                    if (monitor == "triggeronly")
                    {
                        ret = pic.WriteReportToHID(buf, len);
                        System.Threading.Thread.Sleep(100);
                    }

                    ret = pic.ReadReportFromHID(buf, ref len);
                    if (!ret)
                        break;

                    now = DateTime.Now;
                    if (buf[3] == 0x22)  // reading GPS
                    {
                        if (monitor == "all")
                        {
                            int i = 4; // Latitude
                            report = "(" + (char)buf[i++] + (char)buf[i++];
                            report += "^" + (char)buf[i++] + (char)buf[i++] + (char)buf[i++] + (char)buf[i++] + (char)buf[i++] + (char)buf[i++] + (char)buf[i++] + (char)buf[14];

                            i = 16; // Longtitude
                            report += ", " + (char)buf[i++] + (char)buf[i++] + (char)buf[i++];
                            report += "^" + (char)buf[i++] + (char)buf[i++] + (char)buf[i++] + (char)buf[i++] + (char)buf[i++] + (char)buf[i++] + (char)buf[27];

                            i = 29;  // Altitude
                            report += ", " + (char)buf[i++] + (char)buf[i++] + (char)buf[i++] + (char)buf[i++] + (char)buf[i++];

                            i = 36; // GEOID_Altitude
                            report += "m), (" + (char)buf[i++] + (char)buf[i++] + (char)buf[i++] + (char)buf[i++] + (char)buf[i++]; 

                            i = 43; // Speed
                            report += "), (" + (char)buf[i++] + (char)buf[i++] + (char)buf[i++] + (char)buf[i++]; 

                            i = 49; // Time
                            report += "km/h), (" + (char)buf[i++] + (char)buf[i++] + ":" + (char)buf[i++] + (char)buf[i++] + ":" + (char)buf[i++] + (char)buf[i++];

                            i = 56;  // Date
                            report += ", " + (char)buf[i++] + (char)buf[i++] + "/" + (char)buf[i++] + (char)buf[i++] + "/" + (char)buf[i++] + (char)buf[i++];
                            report += ")";

                            Console.WriteLine(now + " : GPS " + report);
                            log.WriteLine(now + " : GPS " + report);
                            log.Flush();
                        }
                        continue;
                    }

                    //len = (buf[2] > 63) ? 63 : buf[2];
                    //checksum = CalculateChecksum(buf, 1, len);
                    ////log = new StreamWriter(logfilename, true);

                    if (buf[3] == 0x24)
                    {
                        //report = BitConverter.ToString(buf, 4, buf[2] - 3);
                        report = "";
                        for (int i = 4; i < buf[2] + 3; i++)
                        {
                            report += i % 4 == 0 ? " " : "";
                            report += buf[i] > 0 ? "^" : "_";
                        }

                        if (display == "all" || report != report0)
                        {
                            Console.WriteLine(now + " : Triggers " + report);
                            log.WriteLine(now + " : Triggers " + report);
                            log.Flush();
                            report0 = report;
                        }
                        continue;
                    }

                    report = BitConverter.ToString(buf, 1, buf[2]);

                    cmd = "";
                    if (buf[3] == 0x41)
                        cmd = "LED ";
                    else if (buf[3] == 0x32)
                        cmd = "MIC ";
                    else if (buf[3] == 0x22)
                        cmd = "Enable Radar ";
                    else if (buf[3] == 0x23)
                        cmd = "Send Radar ";
                    else if (buf[3] == 0xF1)
                        cmd = "Heartbeat ";
                    else if (buf[3] == 0x25)
                        cmd = "Hardware ";
                    else if (buf[3] == 0x37)
                        cmd = "Temperature ";
                    else if (buf[3] == 0x27)
                        cmd = "PIC Reset Reason ";
                    else if (buf[3] == 0x28)
                        cmd = "Battery ";
                    else if (buf[3] == 0x31)
                        cmd = "AV Device ";
                    else if (buf[3] == 0x3A)
                        cmd = "PC Shutdown ";
                    else if (buf[3] == 0xF2)
                        cmd = "Front Camera Reset ";
                    else if (buf[3] == 0xFF && buf[4] == 0x00)
                        cmd = "Invalid Command ";
                    else if (buf[3] == 0xFF && buf[4] == 0x01)
                        cmd = "Invalid Checksum ";
                    else if (buf[3] == 0xFF && buf[4] == 0x02)
                        cmd = "Invalid Radar Data ";
                    else if (buf[3] == 0xFF && buf[4] == 0x03)
                        cmd = "Timeout ";

                    Console.WriteLine(now + " : " + cmd + report);
                    log.WriteLine(now + " : " + cmd + report);
                    log.Flush();
                }
            }

            log.Close();
            System.Threading.Thread.Sleep(20 * 1000);
        }

        static List<USBDeviceInfo> GetUSBDevices()
        {
            List<USBDeviceInfo> devices = new List<USBDeviceInfo>();

            ManagementObjectCollection collection;
            //using (var searcher = new ManagementObjectSearcher(@"Select * From Win32_USBHub"))
            using (var searcher = new ManagementObjectSearcher(@"Select * From Win32_PnPEntity"))
                collection = searcher.Get();

            foreach (var device in collection)
            {
                string deviceID = (string)device.GetPropertyValue("DeviceID");
                if (deviceID.Contains(@"HID\VID_04D8"))
                    devices.Add(new USBDeviceInfo(
                    (string)device.GetPropertyValue("DeviceID"),
                    (string)device.GetPropertyValue("PNPDeviceID"),
                    (string)device.GetPropertyValue("Description"),
                    (string)device.GetPropertyValue("ClassGuid")
                    ));
            }

            collection.Dispose();
            return devices;
        }

        static bool EnterBootLoaderMode()
        {
            Console.WriteLine("The Firmware updater will let the PIC enter boot loader mode.");
            GenericUSBHIDLibrary pic = new GenericUSBHIDLibrary("04d8", "F2BF"); //VID=04D8, PID=003C for boot loader mode, PID=F2BF for firmware mode
            if (!pic.IsFound)
            {
                Console.WriteLine("Cannot find any PIC devices.");
                Console.ReadLine();
                return false;
            }

            Console.WriteLine("Found {0} in firmware mode.", pic.HIDDeviceConnectionString);
            if (pic.Connect())
            {
                bool ret;
                byte[] buf = new byte[65];
                int len = 0;
                buf[len++] = 0;  // The report ID of the HID device. Shall be 00 all the times.
                buf[len++] = 0xB2;  // The header of the CopTrax firmware command.
                buf[len++] = 0x03;  // The length of the CopTrax firmware command. 3 is the shortest one.
                buf[len++] = 0x66; // The command to let the PIC entering boot loader mode.
                buf[len++] = 0xE5; // The checksum of the command, which is NOT(sum(buf[0]..buf[len]) + 1) & 0xFF.

                Console.WriteLine("Sending command to PIC to let it enter boot loader mode.");
                ret = pic.WriteReportToHID(buf, 5);

                Console.WriteLine("Cannot let the PIC enter boot loader mode.");

                ret = pic.ReadReportFromHID(buf, ref len);
                Console.WriteLine("Read reply {0} from PIC.", buf);
                Console.Read();
            }
            return false;
        }

        static void CreateRegistry(string args)
        {
            Microsoft.Win32.RegistryKey key;
            key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run\CopTraxFirmwareUpdater", true);
            if (key == null)
                key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run\CopTraxFirmwareUpdater");

            //string value = key.GetValue("CopTraxFirmwareUpdater").ToString();
            key.SetValue("CopTraxFirmwareUpdater", "\"C:\\CopTrax Support\\Tools\\FirmwareUpdater\\FUT.exe\" " + args);
            key.Close();
            return;
        }

        static void DeleteRegistry()
        {
            Microsoft.Win32.RegistryKey key;
            key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run\CopTraxFirmwareUpdater", true);
            if (key == null)
                return;
            key.DeleteSubKey("CopTraxFirmwareUpdater");
            key.Close();
            return;
        }

        static int CalculateChecksum(byte[] buf, int offset, int length)
        {
            int checksum = 0;
            for (int i = 0; i < length; i++)
                checksum += buf[i + offset];
            return checksum & 0xFF;
        }
    }
}
class USBDeviceInfo
{
    public USBDeviceInfo(string deviceID, string pnpDeviceID, string description, string classGuid)
    {
        this.DeviceID = deviceID;
        this.PnpDeviceID = pnpDeviceID;
        this.Description = description;
        this.ClassGuid = classGuid;
    }
    public string DeviceID { get; private set; }
    public string PnpDeviceID { get; private set; }
    public string Description { get; private set; }
    public string ClassGuid { get; private set; }
}
