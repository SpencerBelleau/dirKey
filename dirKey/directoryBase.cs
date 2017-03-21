using System;
using System.Collections.Generic;
using System.IO;

namespace dirKey
{
	public class directoryBase
	{
		protected List<String> fullNames = new List<string>();
		protected List<String> fullDirs = new List<string>();
		protected DirectoryInfo root;
		public directoryBase()
		{

		}

		public directoryBase(DirectoryInfo root)
		{
			this.root = root;
			walkDirectory(this.root);
		}

		public void walkDirectory()
		{
			walkDirectory(root);
		}

		public void walkDirectory(DirectoryInfo root)
		{
			FileInfo[] fileNames = null;
			DirectoryInfo[] subDirs = null;

			try
			{
				fileNames = root.GetFiles("*");
			}
			catch (Exception e)
			{
				Console.WriteLine("walkDirectory() failure:");
				Console.WriteLine(e.Message);
				return;
			}

			if (fileNames != null)
			{
				foreach (FileInfo name in fileNames)
				{
					fullNames.Add(name.FullName);
				}

				subDirs = root.GetDirectories();

				foreach (DirectoryInfo subDir in subDirs)
				{
					fullDirs.Add(subDir.FullName);
					walkDirectory(subDir);
				}
			}
		}
		/*
		 * This should really be elsewhere
		 */
		public static List<string> getFiles(DirectoryInfo root)
		{
			FileInfo[] fileNames = null;
			DirectoryInfo[] subDirs = null;
			List<string> returnVal = new List<string>();
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
				foreach (FileInfo name in fileNames)
				{
					returnVal.Add(name.FullName);
				}

				subDirs = root.GetDirectories();

				foreach (DirectoryInfo subDir in subDirs)
				{
					returnVal.AddRange(getFiles(subDir));
				}
			}
			return returnVal;
		}

		public List<String> getFileNames()
		{
			return fullNames;
		}

		public List<String> getDirNames()
		{
			return fullDirs;
		}

		public void cleanRoot()
		{
			foreach (string s in fullDirs)
			{
				try
				{
					if (!s.Equals(root.FullName))
					{
						Directory.Delete(s, true);
						Console.WriteLine("Deleting directory: {0}", s);
					}
				}
				catch
				{
					continue;
				}
			}
		}
	}
}
