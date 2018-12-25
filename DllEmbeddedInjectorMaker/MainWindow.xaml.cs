using System;
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

// ONLY WORKS ON DEBUG COMPILE
namespace DllEmbeddedInjectorMaker
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
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

        public static void WriteDlls()
        {
            using (FileStream fs = File.Create("embedingCode.dll"))
            {
                byte[] bytes = readEmbeddedResource("DllEmbeddedInjectorMaker.embedingCode.dll");
                fs.Write(bytes, 0, bytes.Length);
            }
        }

        [DllImport(@"embedingCode.dll", EntryPoint = "?EmbedDllFile@@YAXPEAD0@Z")]
        public static extern void EmbedDllFile(char[] dllFile, char[] InjectorFile);

        public MainWindow()
        {
            InitializeComponent();
            if (!File.Exists("embedingCode.dll"))
            {
                WriteDlls();
            }
        }
        void drop_files(object sender, DragEventArgs e)
        {
            if (e == null)
                return;
            string[] FileList = (string[])e.Data.GetData(DataFormats.FileDrop, false);
            string fileName = FileList[0].Substring(FileList[0].LastIndexOf('\\') + 1);
            string fileExtension = FileList[0].Substring(FileList[0].LastIndexOf('.') + 1);

            if (fileExtension == "dll")
                textBox.Text = fileName;
            else return;

            string outputName = "InjectorWithInbeddedDLL.exe";
            using (FileStream fs = File.Create(outputName))
            {
                byte[] bytes = readEmbeddedResource("DllEmbeddedInjectorMaker.injecotor.exe");

                //offset to injectors target exe is 23F8 
                var offsetAmount = 0x23F8;

                for (int i = 0; i < textBox1.Text.Length; i++) {

                    char value = (char)bytes[offsetAmount];
                    char value2 = (char)textBox1.Text[i];

                    bytes[offsetAmount] = (byte)textBox1.Text[i];
                    offsetAmount++;
                }
                bytes[offsetAmount] = (byte)'\0';

                fs.Write(bytes, 0, bytes.Length);
            }
            string loaction = AppDomain.CurrentDomain.BaseDirectory;
            string targetLoc = loaction + outputName;

            EmbedDllFile(FileList[0].ToCharArray(), targetLoc.ToCharArray());
            Process.Start(loaction );//,"/select, " + outputName
        }

        private void button_Click(object sender, RoutedEventArgs e)
        {
            Process.Start(AppDomain.CurrentDomain.BaseDirectory);
        }

        private void button_Copy_Click(object sender, RoutedEventArgs e)
        {
            drop_files(0, savedEvent);
        }
    }
}
