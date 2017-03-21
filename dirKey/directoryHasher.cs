using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace dirKey
{
	public class directoryHasher : directoryBase
	{
		private SHA512 key = SHA512.Create();
		public directoryHasher()
		{
			
		}

		public directoryHasher(DirectoryInfo root)
		{
			this.root = root;
			walkDirectory(this.root);
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
