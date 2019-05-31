﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Diagnostics;
using System.ComponentModel;


public enum codeType
    {
    x64,
    x86,
    unknowen
}

namespace DllEmbeddedInjectorMaker
{

    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        const string DllLocation = "C:\\ProgramData\\embedingCode.dll";

        DragEventArgs savedEvent = null;

        public static byte[] readEmbeddedResource(string resourceName)
        {
            var assembly = Assembly.GetExecutingAssembly();
            using (Stream resFilestream = assembly.GetManifestResourceStream(resourceName))
            {
                if (resFilestream == null)
                {
                    return null;
                }

                byte[] bytes = new byte[resFilestream.Length];
                resFilestream.Read(bytes, 0, bytes.Length);

                return bytes;
            }
        }

        public static codeType FindDllBitType(string fileLocation)
        {
            byte[] binaryData = File.ReadAllBytes(fileLocation);

            byte[] output = new byte[500];
            Buffer.BlockCopy(binaryData, 0, output, 0, 500);

            char dllType = '\0';

            for(int i=0;i<500;i++) {
                if (output[i] == 'P') {
                    if (output[i + 1] == 'E') {
                        dllType = (char)output[i + 4];
                    }
                }
            }

            if (dllType == 'd')
                return codeType.x64;
            if (dllType == 'L')
                return codeType.x86;
            return codeType.unknowen;
        }

        public static int getDllFromArray(string[] fileList)
        {
            int returnIndex=-1;
            for (int i = 0; i < fileList.Length; i++)
            {
                string fileExtension = fileList[i].Substring(fileList[i].LastIndexOf('.') + 1);
                if (fileExtension == "dll")
                {
                    returnIndex = i;
                }
            }
            return returnIndex;
        }

        public static void WriteDlls(string outputName, string internalName)
        {
            using (FileStream fs = File.Create(outputName))
            {
                byte[] bytes = readEmbeddedResource(internalName);
                fs.Write(bytes, 0, bytes.Length);
            }
        }
        
        [DllImport(DllLocation)]
        public static extern void EmbedDllFile(char[] dllFile, char[] InjectorFile);

        public MainWindow()
        {
            InitializeComponent();

            if (!File.Exists(DllLocation))
            {
                WriteDlls(DllLocation, "DllEmbeddedInjectorMaker.embedingCode.dll");
            }
        }
        void drop_files(object sender, DragEventArgs e)
        {
            if (e == null)
                return;
            savedEvent = e;
            string[] FileList = (string[])e.Data.GetData(DataFormats.FileDrop, false);

            int indexLocation = getDllFromArray(FileList);
            if (indexLocation == -1)
                return;

            string dllLocation = FileList[indexLocation];
            string dllName = dllLocation.Substring(dllLocation.LastIndexOf('\\') + 1);
            textBox.Text = dllName;


            string outputName = "InjectorWithInbeddedDLL.exe";

            string embededdInjector;

            codeType machineType = FindDllBitType(dllLocation);
            switch(machineType){
                case codeType.x64:
                    embededdInjector = "DllEmbeddedInjectorMaker.injector_x64.exe";
                    break;
                case codeType.x86:
                    embededdInjector = "DllEmbeddedInjectorMaker.injector_x86.exe";
                    break;
                default:
                    return;
            }
            if (machineType == codeType.unknowen)
                return;

            using (FileStream fs = File.Create(outputName))
            {
                byte[] bytes = readEmbeddedResource(embededdInjector);

                // find PLACEHOLDER in byte array
                string thingToFind = "PLACEHOLDER";
                UInt32 count = 0;
                bool found = false;
                do {
                    count++;
                    int foundAmount = 0;
                    for (int i = 0; i< thingToFind.Length;i++) {
                        if ((char)bytes[count+i] == thingToFind[i]) {
                            foundAmount++;
                            if (foundAmount== thingToFind.Length-1) {
                                found = true;
                            }
                        } else break;
                    }
                } while (!found);

                var offsetAmount = count;

                for (int i = 0; i < textBox1.Text.Length; i++) {
                    bytes[offsetAmount] = (byte)textBox1.Text[i];
                    offsetAmount++;
                }
                bytes[offsetAmount] = (byte)'\0';

                fs.Write(bytes, 0, bytes.Length);
            }
            string loaction = AppDomain.CurrentDomain.BaseDirectory;
            string targetLoc = loaction + outputName;
            EmbedDllFile(FileList[indexLocation].ToCharArray(), targetLoc.ToCharArray());
            Process.Start(loaction);// open file view expolrer
            return;
        }

        private void button_Click(object sender, RoutedEventArgs e)
        {
            Process.Start(AppDomain.CurrentDomain.BaseDirectory);
        }

        private void button_Copy_Click(object sender, RoutedEventArgs e)
        {
            drop_files(0, savedEvent);
        }

        void closingEvent(object sender, CancelEventArgs e)
        {
#if DEBUG
            // Bug 
            // only deleats if has not been used to create new application.
            File.Delete(DllLocation);
#endif
        }
    }
}
