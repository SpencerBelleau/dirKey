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

			bool debugLog = false;
			if (cliargs.Length == 4)
			{
				command = cliargs[1];
				if (Path.IsPathRooted(cliargs[2]))
				{
					hashPath = cliargs[2];
				}
				else
				{
					hashPath = System.IO.Directory.GetCurrentDirectory() + "\\" + cliargs[2];
				}

				if (Path.IsPathRooted(cliargs[3]))
				{
					encPath = cliargs[3];
				}
				else
				{
					encPath = System.IO.Directory.GetCurrentDirectory() + "\\" + cliargs[3];
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
					hashPath = System.IO.Directory.GetCurrentDirectory() + "\\" + cliargs[2];
				}

				if (Path.IsPathRooted(cliargs[3]))
				{
					encPath = cliargs[3];
				}
				else
				{
					encPath = System.IO.Directory.GetCurrentDirectory() + "\\" + cliargs[3];
				}
				debugLog = true;
			}
			else
			{
				Console.WriteLine("Not enough args.");
				Environment.Exit(-1); //failure
			}
			Console.WriteLine("Hash Path: {0}\nTarget Path: {1}", hashPath, encPath);

			directoryHasher d = new directoryHasher(new System.IO.DirectoryInfo(hashPath));
			//d.walkDirectory(); //create both the hash and a list of filenames in the hash

			/*
			Console.WriteLine(d.getDirNames());
			foreach (string s in d.getDirNames())
			{
				Console.WriteLine(s);
			}
			*/

			keyIterator key = new keyIterator(d.createHash());
			//key.resetKey();

			directoryPacker e = new directoryPacker(new System.IO.DirectoryInfo(encPath), debugLog);//new directoryEncrypter(new System.IO.DirectoryInfo(encPath), debugLog);
			e.walkDirectory();

			if (command.Equals("-e"))
			{
				e.encrypt(key);
			}
			else if (command.Equals("-d"))
			{
				e.decrypt(key);
			}
			else
			{
				Console.WriteLine("Invalid command '{0}'",command);
				Environment.Exit(-1);
			}
			Console.WriteLine("Finished!");
		}
	}
}
