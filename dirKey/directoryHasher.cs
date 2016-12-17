using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace dirKey
{
	public class directoryHasher
	{
		private SHA512 key = SHA512.Create();
		private List<String> fullNames = new List<string>();
		private List<String> fullDirs = new List<string>();
		private System.IO.DirectoryInfo root;
		public directoryHasher()
		{
			
		}

		public directoryHasher(System.IO.DirectoryInfo root)
		{
			this.root = root;
			walkDirectory(this.root);
		}

		public void walkDirectory()
		{
			walkDirectory(this.root);
		}

		public void walkDirectory(System.IO.DirectoryInfo root)
		{
			System.IO.FileInfo[] fileNames = null;
			System.IO.DirectoryInfo[] subDirs = null;

			try
			{
				fileNames = root.GetFiles("*");
			}
			catch (Exception e)
			{
				Console.WriteLine(e.Message);
			}

			if (fileNames != null)
			{
				foreach (System.IO.FileInfo name in fileNames)
				{
					//Log it
					//Console.WriteLine(name.FullName);
					fullNames.Add(name.FullName);
				}

				subDirs = root.GetDirectories();

				foreach (System.IO.DirectoryInfo subDir in subDirs)
				{
					fullDirs.Add(subDir.FullName);
					walkDirectory(subDir);
				}
			}
		}

		public List<String> getFileNames()
		{
			return fullNames;
		}

		public List<String> getDirNames()
		{
			return fullDirs;
		}

		public byte[] createHash()
		{
			byte[] hash = null;
			foreach (String s in fullNames)
			{
				//Console.WriteLine("Computing hash for: {0}", s);
				using (var stream = File.OpenRead(s))
				{
					//extend out the hash to 256 bytes, so the encryption works better
					byte[] fileHash = new byte[256];
					key.ComputeHash(stream).CopyTo(fileHash, 0);
					key.ComputeHash(fileHash).CopyTo(fileHash, 64);
					key.ComputeHash(fileHash).CopyTo(fileHash, 128);
					key.ComputeHash(fileHash).CopyTo(fileHash, 192);

					if (hash == null)
					{
						hash = fileHash;
					}
					else
					{
						//basically combine the old hash and the new hash
						List<byte> joinList = new List<byte>();
						joinList.AddRange(hash);
						joinList.AddRange(fileHash);
						hash = joinList.ToArray();
					}
				}
			}

			return hash;
		}
	}
}
