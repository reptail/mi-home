﻿using System;
using MiHomeLib.Commands;
using MiHomeLib.Transport;
using Newtonsoft.Json.Linq;
#pragma warning disable CS0675

namespace MiHomeLib.Devices
{
    public class Gateway : MiHomeDevice
    {
        private readonly ITransport _transport;

        public Gateway(string sid, ITransport transport) : base(sid, "gateway")
        {
            _transport = transport;
        }

        public string Rgb { get; private set; }
        public string Illumination { get; private set; }
        public string ProtoVersion { get; private set; }

        public override void ParseData(string command)
        {
            var jObject = JObject.Parse(command);

            if (jObject["rgb"] != null)
            {
                Rgb = jObject["rgb"].ToString();
            }

            if (jObject["illumination"] != null)
            {
                Illumination = jObject["illumination"].ToString();
            }

            if (jObject["proto_version"] != null)
            {
                ProtoVersion = jObject["proto_version"].ToString();
            }
        }

        public override string ToString()
        {
            return $"Rgb: {Rgb}, Illumination: {Illumination}, ProtoVersion: {ProtoVersion}";
        }

        public void EnableLight(byte r = 255, byte g = 255, byte b = 255, int illumination = 1000)
        {
            var rgb = 0xFF000000 | r << 16 | g << 8 | b; // found this trick from chinise gateway docs 

            if (illumination < 300 || illumination > 1300) throw new ArgumentException("Illumination must be in range 300 - 1300");

            _transport.SendWriteCommand(Sid, Type, new GatewayLightCommand(rgb, illumination));
        }

        public void DisableLight()
        {
            _transport.SendWriteCommand(Sid, Type, new GatewayLightCommand(0, 0));
        }

        public void StartPlayMusic(int midNo = 0)
        {
            if(midNo <= 0 || midNo == 9 || midNo > 13 && midNo < 20 || midNo > 29) throw new ArgumentException("Mid No must be in range 0-8 or 10-13 or 20-29");

            _transport.SendWriteCommand(Sid, Type, new GatewayMusicCommand(midNo));
        }

        public void StopPlayMusic()
        {
            _transport.SendWriteCommand(Sid, Type, new GatewayMusicCommand(1000));
        }
    }
}