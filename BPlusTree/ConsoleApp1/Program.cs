using BPlusTree;
using System;
using System.IO;

namespace BPlusTreeTest
{
    class Program
    {
        private const string TreeDataDir = @"D:\tmp";
        private const int DefaultNodeSize = 32;
        private const int DefaultKeyLength = 32;
        private static BplusTreeLong _treeProperty;
        private const string SmsContent = "数字签名可以保证信息的原始性、完整性。因此，数字签名可以解决否认、伪造、篡改及冒充等问题。具体要求：发送：昔事后不能否认发送的报文签名、接收者能够核实发送者发送的报文签名、接收者不能伪造发送者的报文签名、接收者不能对发送者的报文进行部分篡改、网络中的某一用户不能冒充另一用户作为发送者或接收者。数字签名的应用范围十分广泛，在保障电子数据交换(EDI)的安全性上是一个突破性的进展，凡是需要对用户的身份进行判断的情况都可以使用数字签名，比如加密信件、商务信函、定货购买系统、远程金融交易、电子政务、自动模式处理等等。 ";
        private const int StatCount = 10000;
        private static readonly int LcId = System.Globalization.CultureInfo.InvariantCulture.LCID;

        static void Main(string[] args)
        {
            if (!Directory.Exists(TreeDataDir))
            {
                Directory.CreateDirectory(TreeDataDir);
            }

            Process();
        }

        private static void Process()
        {
            var stopwatch = new System.Diagnostics.Stopwatch();
            var index = 1;
            var batchIndex = 1;
            for (int i = 0; i < 1000000; i++)
            {
                if (index == 1)
                {
                    stopwatch.Start();
                }

                // var key = FormsAuthentication.HashPasswordForStoringInConfigFile(SmsContent + i, "MD5");
                var key = i.ToString() + "ssss";
                if (!TreeProperty.ContainsKey(key))
                {
                    try
                    {
                        TreeProperty[key] = i;
                        TreeProperty.Commit();
                    }
                    catch (Exception ex)
                    {
                        TreeProperty.Shutdown();
                        _treeProperty = null;
                        var keyFile = Path.Combine(TreeDataDir, TreeFileName);
                        if (File.Exists(keyFile))
                        {
                            File.Delete(keyFile);
                            Console.WriteLine("Delete The Bad Key File Done!");
                        }

                        TreeProperty[key] = i;
                        TreeProperty.Commit();
                    }

                }
                else
                {
                    Console.WriteLine("ContainsKey:" + key);
                }

                index++;

                if (index == StatCount)
                {
                    stopwatch.Stop();
                    var spendSeconds = stopwatch.Elapsed.TotalSeconds;
                    var speed = StatCount / spendSeconds;
                    Console.WriteLine(batchIndex + ".Speed:" + speed.ToString("0.00") + "/s");
                    stopwatch.Reset();
                    index = 1;
                    batchIndex++;
                }
            }

            TreeProperty.Shutdown();
            Console.WriteLine("Done!");
            Console.ReadLine();
        }

        private static BplusTreeLong TreeProperty
        {
            get
            {
                var treeFilePath = Path.Combine(TreeDataDir, TreeFileName);
                if (_treeProperty == null)
                {
                    if (File.Exists(treeFilePath))
                    {
                        Console.WriteLine("Re-Opent A Existing Tree(Maybe The App Had An Restarting)");
                        _treeProperty = BplusTreeLong.SetupFromExistingStream(
                            new FileStream(treeFilePath, FileMode.Open, FileAccess.ReadWrite),
                            treeFilePath
                            );

                        return _treeProperty;
                    }

                    Console.WriteLine("Create A New Tree In The First Time");
                    _treeProperty = BplusTreeLong.InitializeInStream(
                        new FileStream(treeFilePath, FileMode.CreateNew, FileAccess.ReadWrite),
                        treeFilePath,
                        DefaultKeyLength,
                        DefaultNodeSize,
                        LcId);
                    return _treeProperty;
                }

                if (string.IsNullOrEmpty(_treeProperty.FromFilePath))
                {
                    throw new Exception("BplusTreeLong.FromFilePath Is Null Or Empty! Please Call The Right Funcation To Get An BplusTreeLong Instance.");
                }

                if (!string.Equals(_treeProperty.FromFilePath, treeFilePath, StringComparison.OrdinalIgnoreCase))
                {
                    _treeProperty.Shutdown();
                    if (File.Exists(_treeProperty.FromFilePath))
                    {
                        File.Delete(_treeProperty.FromFilePath);
                        Console.WriteLine("Delete The Old Key File Done!");
                    }

                    _treeProperty = BplusTreeLong.InitializeInStream(
                        new FileStream(treeFilePath, FileMode.CreateNew, FileAccess.ReadWrite),
                        treeFilePath,
                        DefaultKeyLength,
                        DefaultNodeSize,
                        LcId
                        );
                }

                return _treeProperty;
            }
        }

        private static string TreeFileName
        {
            get
            {
                return "KeyFile" + DateTime.Now.ToString("yyyyMMddhhmm") + ".key";
            }
        }
    }
}
