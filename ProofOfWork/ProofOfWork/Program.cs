using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProofOfWork
{
    public class Proof
    {
        public string Hash { get; private set; }
        public long Nonce { get; private set; }

        public int NrLeadingZeros { get; private set; }

        public long CreatedAt { get; private set; }

        public Proof(string hash, long createdAt, long nonce, int nrLeadingZeros)
        {
            this.Hash = hash;
            this.Nonce = nonce;
            this.CreatedAt = createdAt;
            this.NrLeadingZeros = nrLeadingZeros;
        }

        public override string ToString()
        {
            return "ProofOfWork [sha512Hash=" + Hash
                + ", createdAt=" + CreatedAt
                + ", nonce=" + Nonce
                + ", leadingZeros=" + NrLeadingZeros + "]";
        }
    }

    class Program
    {
        static Random random = new Random(3 /* for testing only*/);

        static void Main(string[] args)
        {
            string data = "dit is een test";
            var dataBytes = Encoding.UTF8.GetBytes(data);
            var res = Work(dataBytes, 3);

            var ret = Verify(dataBytes, res, new TimeSpan(2, 0, 0));
            Console.WriteLine($"Proof:{ret} - {res}");
            Console.ReadLine();
        }

        static long RandomLong(Random rand)
        {
            byte[] bytes = new byte[8];
            rand.NextBytes(bytes);
            return BitConverter.ToInt64(bytes, 0);
        }

        static byte[] ComputeSHA512(byte[] data)
        {
            System.Security.Cryptography.SHA512Managed crypt = new System.Security.Cryptography.SHA512Managed();
            return crypt.ComputeHash(data, 0, data.Length);
        }

        static long SecondsSinceEpoch()
        {
            TimeSpan t = DateTime.UtcNow - new DateTime(1970, 1, 1);
            return (int)t.TotalSeconds;
        }

        public static Proof Work(byte[] data, int leadingZeros)
        {
            var createdAt = SecondsSinceEpoch();

            var stream = new MemoryStream();
            var buffer = new BinaryWriter(stream);
            buffer.Write(data);
            buffer.Write(BitConverter.GetBytes(createdAt));

            var leading = "";
            for (int i = 0; i < leadingZeros; i++)
                leading += "0";

            var nonce = 0L;
            while (true)
            {
                nonce = RandomLong(Program.random);
                /* move to right after the data + the createdAt date */
                buffer.Seek(data.Length + sizeof(long), SeekOrigin.Begin);
                buffer.Write(BitConverter.GetBytes(nonce));
                buffer.Flush();

                byte[] hash = ComputeSHA512(stream.GetBuffer());
                string hashString = BitConverter.ToString(hash).Replace("-", "");
                if (hashString.StartsWith(leading))
                {
                    return new Proof(hashString, createdAt, nonce, leadingZeros);
                }
            }
        }

        public static bool Verify(byte[] data, Proof proof, TimeSpan expiration)
        {
            TimeSpan t = DateTime.UtcNow - new DateTime(1970, 1, 1);
            int secondsSinceEpoch = (int)t.TotalSeconds;

            long now = secondsSinceEpoch;
            if (proof.Hash.Length != 128 || now - proof.CreatedAt > expiration.TotalSeconds || proof.NrLeadingZeros < 1 || proof.Hash.Length < proof.NrLeadingZeros)
                return false;

            var leading = "";
            for (int i = 0; i < proof.NrLeadingZeros; i++)
                leading += "0";

            if (!proof.Hash.StartsWith(leading))
                return false;

            var stream = new MemoryStream();
            BinaryWriter buffer = new BinaryWriter(stream);
            buffer.Write(data);
            buffer.Write(BitConverter.GetBytes(proof.CreatedAt));
            buffer.Write(BitConverter.GetBytes(proof.Nonce));
            buffer.Flush();

            byte[] hash = ComputeSHA512(stream.GetBuffer());
            string hashString = BitConverter.ToString(hash).Replace("-", "");
            return hashString.Equals(proof.Hash);
        }
    }
}
