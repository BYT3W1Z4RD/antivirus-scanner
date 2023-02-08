using System;
using System.Net.Http;
using System.IO;
using System.Threading.Tasks;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Runtime.Intrinsics.X86;
using System.Reflection;

namespace VirusTotalUploader
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("Enter file directory:");
            var filePath = Console.ReadLine();
            if (!File.Exists(filePath))
            {
                Console.WriteLine("File does not exist.");
                Console.ReadLine();
                return;
            }

            var apikey = "eb8829c26e9bf50dae94baf9ab6aa60b6bed6acb195ad52d155a7b41f23d7792";
            var fileBytes = File.ReadAllBytes(filePath);
            var fileName = Path.GetFileName(filePath);

            using (var httpClient = new HttpClient())
            {
                httpClient.DefaultRequestHeaders.Add("x-apikey", apikey);
                static string GetSHA256Hash(byte[] fileBytes)
                {
                    using (var sha256Hash = SHA256.Create())
                    {
                        var hash = sha256Hash.ComputeHash(fileBytes);
                        return BitConverter.ToString(hash).Replace("-", "").ToLower();
                    }
                }
                var sha256Hash = GetSHA256Hash(fileBytes);

                using (var formData = new MultipartFormDataContent())
                {
                    var fileContent = new ByteArrayContent(fileBytes);
                    fileContent.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
                    {
                        Name = "file",
                        FileName = fileName
                    };

                    formData.Add(fileContent);

                    var response = await httpClient.PostAsync("https://www.virustotal.com/api/v3/files", formData);

                    if (response.IsSuccessStatusCode)
                    {
                        var scanResult = await response.Content.ReadAsStringAsync();
                        Console.Clear();
                        Console.WriteLine("Scan Successful");
                        Thread.Sleep(5);
                        var client = new HttpClient();
                        var scantimerequest = new HttpRequestMessage
                        {
                            Method = HttpMethod.Get,
                            RequestUri = new Uri("https://www.virustotal.com/api/v3/files/" + sha256Hash),
                            Headers =
                            {
                                { "accept", "application/json" },
                                { "x-apikey", apikey },
                            },
                        };
                        var runtimerequest = new HttpRequestMessage
                        {
                            Method = HttpMethod.Get,
                            RequestUri = new Uri("https://www.virustotal.com/api/v3/files/" + sha256Hash + "/behaviour_summary"),
                            Headers =
                            {
                                {"accept","application/json"}
                            },
                        };
                        using (var scantimeresponse = await client.SendAsync(scantimerequest))
                        {
                            scantimeresponse.EnsureSuccessStatusCode();
                            var body = await scantimeresponse.Content.ReadAsStringAsync();
                            var result = JsonConvert.DeserializeObject<dynamic>(body);
                            try
                            {
                                Console.Clear();
                                Console.Beep();
                                Console.WriteLine("");
                                Console.WriteLine("Filename: " + result.data.attributes.meaningful_name);
                                Console.WriteLine("SHA-256: " + result.data.attributes.sha256);
                                Console.WriteLine("MD5: " + result.data.attributes.md5);
                                Console.WriteLine("URL: https://www.virustotal.com/api/v3/files/" + sha256Hash);
                                Console.WriteLine("");
                                Console.WriteLine("Detection Rate: " + result.data.attributes.last_analysis_stats.malicious + "/70");
                                Console.WriteLine("Bypass Rate: " + result.data.attributes.last_analysis_stats.undetected + "/70");
                                Console.WriteLine("");
                                Console.WriteLine("Bkav: " + result.data.attributes.last_analysis_results.Bkav.category);
                                Console.WriteLine("Lionic: " + result.data.attributes.last_analysis_results.Lionic.category);
                                Console.WriteLine("tehtris: " + result.data.attributes.last_analysis_results.tehtris.category);
                                Console.WriteLine("MicroWorld-eScan: " + result.data.attributes.last_analysis_results["MicroWorld-eScan"].category);
                                Console.WriteLine("CAT-QuickHeal: " + result.data.attributes.last_analysis_results["CAT-QuickHeal"].category);
                                Console.WriteLine("ALYac: " + result.data.attributes.last_analysis_results.ALYac.category);
                                Console.WriteLine("Cylance: " + result.data.attributes.last_analysis_results.Cylance.category);
                                Console.WriteLine("Zillya: " + result.data.attributes.last_analysis_results.Zillya.category);
                                Console.WriteLine("Sangfor: " + result.data.attributes.last_analysis_results.Sangfor.category);
                                Console.WriteLine("K7AntiVirus: " + result.data.attributes.last_analysis_results.K7AntiVirus.category);
                                Console.WriteLine("Alibaba: " + result.data.attributes.last_analysis_results.Alibaba.category);
                                Console.WriteLine("K7GW: " + result.data.attributes.last_analysis_results.K7GW.category);
                                Console.WriteLine("Cybereason: " + result.data.attributes.last_analysis_results.Cybereason.category);
                                Console.WriteLine("Baidu: " + result.data.attributes.last_analysis_results.Baidu.category);
                                Console.WriteLine("VirIT: " + result.data.attributes.last_analysis_results.VirIT.category);
                                Console.WriteLine("Cyren: " + result.data.attributes.last_analysis_results.Cyren.category);
                                Console.WriteLine("SymantecMobileInsight: " + result.data.attributes.last_analysis_results.SymantecMobileInsight.category);
                                Console.WriteLine("Symantec: " + result.data.attributes.last_analysis_results.Symantec.category);
                                Console.WriteLine("ESET-NOD32: " + result.data.attributes.last_analysis_results["ESET-NOD32"].category);
                                Console.WriteLine("APEX: " + result.data.attributes.last_analysis_results.APEX.category);
                                Console.WriteLine("Paloalto: " + result.data.attributes.last_analysis_results.Paloalto.category);
                                Console.WriteLine("ClamAV: " + result.data.attributes.last_analysis_results.ClamAV.category);
                                Console.WriteLine("Kaspersky: " + result.data.attributes.last_analysis_results.Kaspersky.category);
                                Console.WriteLine("BitDefender: " + result.data.attributes.last_analysis_results.BitDefender.category);
                                Console.WriteLine("NANO-Antivirus: " + result.data.attributes.last_analysis_results["NANO-Antivirus"].category);
                                Console.WriteLine("SUPERAntiSpyware: " + result.data.attributes.last_analysis_results.SUPERAntiSpyware.category);
                                Console.WriteLine("Avast: " + result.data.attributes.last_analysis_results.Avast.category);
                                Console.WriteLine("Tencent: " + result.data.attributes.last_analysis_results.Tencent.category);
                                Console.WriteLine("Trustlook: " + result.data.attributes.last_analysis_results.Trustlook.category);
                                Console.WriteLine("TACHYON: " + result.data.attributes.last_analysis_results.TACHYON.category);
                                Console.WriteLine("Sophos: " + result.data.attributes.last_analysis_results.Sophos.category);
                                Console.WriteLine("F-Secure: " + result.data.attributes.last_analysis_results["F-Secure"].category);
                                Console.WriteLine("DrWeb: " + result.data.attributes.last_analysis_results.DrWeb.category);
                                Console.WriteLine("VIPRE: " + result.data.attributes.last_analysis_results.VIPRE.category);
                                Console.WriteLine("TrendMicro: " + result.data.attributes.last_analysis_results.TrendMicro.category);
                                Console.WriteLine("McAfee-GW-Edition: " + result.data.attributes.last_analysis_results["McAfee-GW-Edition"].category);
                                Console.WriteLine("Trapmine: " + result.data.attributes.last_analysis_results.Trapmine.category);
                                Console.WriteLine("CMC: " + result.data.attributes.last_analysis_results.CMC.category);
                                Console.WriteLine("Emsisoft: " + result.data.attributes.last_analysis_results.Emsisoft.category);
                                Console.WriteLine("SentinelOne: " + result.data.attributes.last_analysis_results.SentinelOne.category);
                                Console.WriteLine("GData: " + result.data.attributes.last_analysis_results.GData.category);
                                Console.WriteLine("Jiangmin: " + result.data.attributes.last_analysis_results.Jiangmin.category);
                                Console.WriteLine("Webroot: " + result.data.attributes.last_analysis_results.Webroot.category);
                                Console.WriteLine("Google: " + result.data.attributes.last_analysis_results.Google.category);
                                Console.WriteLine("Avira: " + result.data.attributes.last_analysis_results.Avira.category);
                                Console.WriteLine("Antiy-AVL: " + result.data.attributes.last_analysis_results["Antiy-AVL"].category);
                                Console.WriteLine("Kingsoft: " + result.data.attributes.last_analysis_results.Kingsoft.category);
                                Console.WriteLine("Gridinsoft: " + result.data.attributes.last_analysis_results.Gridinsoft.category);
                                Console.WriteLine("Xcitium: " + result.data.attributes.last_analysis_results.Xcitium.category);
                                Console.WriteLine("Arcabit: " + result.data.attributes.last_analysis_results.Arcabit.category);
                                Console.WriteLine("ViRobot: " + result.data.attributes.last_analysis_results.ViRobot.category);
                                Console.WriteLine("ZoneAlarm: " + result.data.attributes.last_analysis_results.ZoneAlarm.category);
                                Console.WriteLine("Avast-Mobile: " + result.data.attributes.last_analysis_results["Avast-Mobile"].category);
                                Console.WriteLine("Windows Defender: " + result.data.attributes.last_analysis_results.Microsoft.category);
                                Console.WriteLine("Cynet: " + result.data.attributes.last_analysis_results.Cynet.category);
                                Console.WriteLine("BitDefenderFalx: " + result.data.attributes.last_analysis_results.BitDefenderFalx.category);
                                Console.WriteLine("AhnLab-V3: " + result.data.attributes.last_analysis_results["AhnLab-V3"].category);
                                Console.WriteLine("Acronis: " + result.data.attributes.last_analysis_results.Acronis.category);
                                Console.WriteLine("McAfee: " + result.data.attributes.last_analysis_results.McAfee.category);
                                Console.WriteLine("MAX: " + result.data.attributes.last_analysis_results.MAX.category);
                                Console.WriteLine("VBA32: " + result.data.attributes.last_analysis_results.VBA32.category);
                                Console.WriteLine("Malwarebytes: " + result.data.attributes.last_analysis_results.Malwarebytes.category);
                                Console.WriteLine("Zoner: " + result.data.attributes.last_analysis_results.Zoner.category);
                                Console.WriteLine("TrendMicro-HouseCall: " + result.data.attributes.last_analysis_results["TrendMicro-HouseCall"].category);
                                Console.WriteLine("Rising: " + result.data.attributes.last_analysis_results.Rising.category);
                                Console.WriteLine("Yandex: " + result.data.attributes.last_analysis_results.Yandex.category);
                                Console.WriteLine("Ikarus: " + result.data.attributes.last_analysis_results.Ikarus.category);
                                Console.WriteLine("MaxSecure: " + result.data.attributes.last_analysis_results.MaxSecure.category);
                                Console.WriteLine("Fortinet: " + result.data.attributes.last_analysis_results.Fortinet.category);
                                Console.WriteLine("BitDefenderTheta: " + result.data.attributes.last_analysis_results.BitDefenderTheta.category);
                                Console.WriteLine("AVG: " + result.data.attributes.last_analysis_results.AVG.category);
                                Console.WriteLine("Panda: " + result.data.attributes.last_analysis_results.Panda.category);
                                Console.WriteLine("CrowdStrike: " + result.data.attributes.last_analysis_results.CrowdStrike.category);
                                Console.ReadLine();
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine("An error has occurred: " + ex.Message);
                                Console.ReadLine();
                            };
                        }
                        using (var runtimeresponse = await client.SendAsync(runtimerequest))
                        {
                            runtimeresponse.EnsureSuccessStatusCode();
                            var body = await runtimeresponse.Content.ReadAsStringAsync();
                            var result = JsonConvert.DeserializeObject<dynamic>(body);
                            try
                            {
                                Console.Clear();
                                Console.Beep();
                                Console.WriteLine("");
                                Console.WriteLine("");
                                Console.WriteLine("");
                                Console.WriteLine("Highlighted Calls:");
                                Console.WriteLine(result.data.calls_highlighted);
                                Console.WriteLine("");
                                Console.WriteLine("Opened Files::");
                                Console.WriteLine(result.data.files_opened);
                                Console.WriteLine("");
                                Console.WriteLine("Loaded Modules:");
                                Console.WriteLine(result.data.modules_loaded);
                                Console.WriteLine("");
                                Console.WriteLine("Created Mutexes:");
                                Console.WriteLine(result.data.mutexes_created);
                                Console.WriteLine("");
                                Console.WriteLine("Opened Mutexes:");
                                Console.WriteLine(result.data.mutexes_opened);
                                Console.WriteLine("");
                                Console.WriteLine("Porcesses Terminated:");
                                Console.WriteLine(result.data.processes_terminated);
                                Console.WriteLine("");
                                Console.WriteLine("Process Tree:");
                                Console.WriteLine(result.data.processes_tree);
                                Console.WriteLine("");
                                Console.WriteLine("Opened Registry Keys:");
                                Console.WriteLine(result.data.registry_keys_opened);
                                Console.WriteLine("");
                                Console.WriteLine("Tags:");
                                Console.WriteLine(result.data.tags);
                                Console.WriteLine("");
                                Console.WriteLine("Highlighted Text:");
                                Console.WriteLine(result.data.text_highlighted);
                                Console.WriteLine("");
                                Console.WriteLine("Mitre Attack Techniques:");
                                Console.WriteLine(result.data.attack_techniques);
                                Console.ReadLine();
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine("An error has occurred: " + ex.Message);
                                Console.ReadLine();
                            };
                        }
                    }
                    else
                    {
                        Console.WriteLine("Error Status Code: " + (int)response.StatusCode);
                        var responseContent = await response.Content.ReadAsStringAsync();
                        Console.WriteLine("Error Response: " + responseContent);
                        Console.ReadLine();
                    }
                }
            }
        }
    }
}