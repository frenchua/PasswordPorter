// See https://aka.ms/new-console-template for more information
using System.Reflection.PortableExecutable;

Console.WriteLine("Hello, World!");

SECItem si;
unsafe
{
    si.data = (char *)0;
    si.type = 0;
    si = FireFoxNSS.NSS_Init("/");
    Console.WriteLine(si.type);
}

