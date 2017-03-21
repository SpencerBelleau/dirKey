using System;
using System.IO;

namespace dirKey
{
	class MainClass
	{
		public static void Main(string[] args)
		{
			//First arg is always the executable name
			String[] cliargs = Environment.GetCommandLineArgs();
			String hashPath = null;
			String encPath = null;
			String command = null;
			String appendPath = null;
			bool debugLog = false;
			bool decryptFile = false;

			if (cliargs.Length == 4)
			{
				command = cliargs[1];
				if (Path.IsPathRooted(cliargs[2]))
				{
					hashPath = cliargs[2];
				}
				else
				{
					hashPath = Directory.GetCurrentDirectory() + "\\" + cliargs[2];
				}

				if (Path.IsPathRooted(cliargs[3]))
				{
					encPath = cliargs[3];
				}
				else
				{
					encPath = Directory.GetCurrentDirectory() + "\\" + cliargs[3];
				}
			}
			else if (cliargs.Length > 4)
			{
				command = cliargs[1];
				if (Path.IsPathRooted(cliargs[2]))
				{
					hashPath = cliargs[2];
				}
				else
				{
					hashPath = Directory.GetCurrentDirectory() + "\\" + cliargs[2];
				}

				if (Path.IsPathRooted(cliargs[3]))
				{
					encPath = cliargs[3];
				}
				else
				{
					encPath = Directory.GetCurrentDirectory() + "\\" + cliargs[3];
				}
				//----------------------
				if (!command.Equals("-a"))
				{
					debugLog = true;
				}
				else
				{
					if (Path.IsPathRooted(cliargs[4]))
					{
						appendPath = cliargs[4];
					}
					else
					{
						appendPath = Directory.GetCurrentDirectory() + "\\" + cliargs[4];
					}
				}
			}
			else
			{
				Console.WriteLine("Not enough args.");
				Environment.Exit(-1); //failure
			}
			//Console.WriteLine("Hash Path: {0}\nTarget Path: {1}", hashPath, encPath);
			Console.Write("\n");
			directoryHasher hasher = new directoryHasher(new DirectoryInfo(hashPath));
			//d.walkDirectory(); //create both the hash and a list of filenames in the hash

			/*
			Console.WriteLine(d.getDirNames());
			foreach (string s in d.getDirNames())
			{
				Console.WriteLine(s);
			}
			*/

			keyIterator key = new keyIterator(hasher.createHash());
			//key.resetKey();

			if (isFile(encPath))
			{
				decryptFile = true;
			}



			if (command.Equals("-e"))
			{
				//Console.WriteLine("Encryption mode");
				directoryPacker packer = new directoryPacker(new DirectoryInfo(encPath), debugLog);//new directoryEncrypter(new System.IO.DirectoryInfo(encPath), debugLog);
				packer.walkDirectory();
				packer.encrypt(key);
			}
			else if (command.Equals("-d"))
			{
				//Console.WriteLine("Decryption mode");
				if (!decryptFile)
				{
					//Console.WriteLine("Directory Mode");
					directoryUnpacker unpacker = new directoryUnpacker(new DirectoryInfo(encPath), debugLog);
					unpacker.walkDirectory();
					unpacker.decrypt(key);
				}
				else
				{
					//Console.WriteLine("File Mode");
					directoryUnpacker unpacker = new directoryUnpacker(new DirectoryInfo(encPath), debugLog);
					//no walk needed
					unpacker.decryptSingle(key, encPath);
				}
			}
			else if (command.Equals("-l"))
			{
				//Console.WriteLine("List Mode");
				if (decryptFile)
				{
					//Console.WriteLine("Listing contents of package: {0}", encPath);
					packageManipulator manipulator = new packageManipulator(new DirectoryInfo(encPath), debugLog);//new directoryEncrypter(new System.IO.DirectoryInfo(encPath), debugLog);
																												  //e.walkDirectory();
					manipulator.listPackage(key, encPath);
				}
				else
				{
					Console.WriteLine("No Package Selected");
				}
			}
			else if (command.Equals("-a"))
			{
				if (!isFile(appendPath))
				{
					Console.WriteLine("CURRENTLY CANNOT APPEND DIRECTORY");
				}
				Console.WriteLine("WARNING: NO SAFETIES CURRENTLY IN PLACE TO PREVENT PACKAGE CORRUPTION");
				packageManipulator manipulator = new packageManipulator(new DirectoryInfo(encPath), true);
				manipulator.appendPackage(key, encPath, appendPath);
			}
			else
			{
				Console.WriteLine("Invalid command '{0}'", command);
				Environment.Exit(-1);
			}
			Console.WriteLine("Finished!");
		}

		public static String BytesToString(long byteCount)
		{
			string[] suf = { "B", "KB", "MB", "GB", "TB", "PB", "EB" }; //Longs run out around EB
			if (byteCount == 0)
				return "0" + suf[0];
			long bytes = Math.Abs(byteCount);
			int place = Convert.ToInt32(Math.Floor(Math.Log(bytes, 1024)));
			double num = Math.Round(bytes / Math.Pow(1024, place), 1);
			return (Math.Sign(byteCount) * num) + suf[place];
		}

		public static bool isFile(string s)
		{
			FileAttributes attr = File.GetAttributes(s);

			//detect whether its a directory or file
			if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
				return false;
			return true;
		}
	}
}
