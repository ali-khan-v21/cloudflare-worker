const maxPerType = 50;

const how_old = 5;

const how_many = 50;

const blacklist_provider = ["ircf.space"];

const whitelist_operator = ["MKH", "MTN", "MCI", "RTL", "HWB", "FNV", "ARX"];

const myConfigs = [
];
  //'vmess://ewogICJ2IjogIjIiLAogICJwcyI6ICJDTElFTlQtYWRtaW4iLAogICJhZGQiOiAidTIubXlza3ljbG91ZC5zcGFjZSIsCiAgInBvcnQiOiA4NDQzLAogICJpZCI6ICJlNTU1ZDFkYi1lNzlmLTQzNTctYTJjYy1kNTdhM2UwNDY0YjAiLAogICJhaWQiOiAwLAogICJuZXQiOiAid3MiLAogICJ0eXBlIjogIm5vbmUiLAogICJ0bHMiOiAidGxzIiwKICAicGF0aCI6ICIvc2t5IiwKICAic25pIjogInUyLm15c2t5Y2xvdWQuc3BhY2UiLAogICJhbHBuIjogImgyLGh0dHAvMS4xIgp9'

// Clean IPS
const cleanIPPerOperator = {
  MKB: ["mkh.ircf.space", "mkhx.ircf.space"],
  IRC: ["mtn.ircf.space", "mtnx.ircf.space", "mtnc.ircf.space"],
  MCI: ["mci.ircf.space", "mcix.ircf.space", "mcic.ircf.space"],
  RTL: ["rtl.ircf.space"],
  MBT: ["mbt.ircf.space"],
  HWB: ["hwb.ircf.space"],
  AST: ["ast.ircf.space"],
  PRS: ["prs.ircf.space"],
  SHT: ["sht.ircf.space"],
  SHM: ["shm.ircf.space"],
  ZTL: ["ztl.ircf.space"],
  ASK: ["ask.ircf.space"],
  RSP: ["rsp.ircf.space"],
  AFN: ["afn.ircf.space"],
  PSM: ["psm.ircf.space"],
  ARX: ["arx.ircf.space"],
  SMT: ["smt.ircf.space"],
  FNV: ["fnv.ircf.space"],
  APT: ["apt.ircf.space"],
  DBN: ["dbn.ircf.space"],
  OTH: [],
};

const addressList = ["discord.com", "cloudflare.com", "nginx.com", "cdnjs.com"];

const fpList = [
  "",
  "chrome",
  "chrome",
  "chrome",
  "firefox",
  "safari",
  "edge",
  "ios",
  "android",
  "randomized",
  "randomized",
  "random",
  "random",
];

const alpnList = ["", "http/1.1", "h2,http/1.1", "h2,http/1.1"];

var cleanIP = "";

export default {
  async fetch(request) {
    var url = new URL(request.url);
    var pathParts = url.pathname.replace(/^\/|\/$/g, "").split("/");
    var type = pathParts[0].toLowerCase();
    if (type == "sub") {
      if(url.searchParams.has('config')){
        myConfigs.push(
            url.searchParams.get("config"),
        );
      }
      if (pathParts[1] !== undefined) {
        
        myConfigs.push("vmess://"+pathParts[1].trim());
        console.log(myConfigs[0]);
      }

      var configList = [];
      var vmessConfigList = configList.filter(
        (cnf) => cnf.search("vmess://") == 0
      );
      var trojanConfigList = configList.filter(
        (cnf) => cnf.search("trojan://") == 0
      );
      var ssConfigList = configList.filter((cnf) => cnf.search("ss://") == 0);
      var finalConfigList = [];

      var ipList = [];
      if (cleanIP) {
        ipList = { GEN: [cleanIP] };
      } else {
        cleanIPPerOperator.OTH = await fetchData();
        ipList = { ...cleanIPPerOperator };
        Object.keys(ipList).forEach(
          (k) => !ipList[k].length && delete ipList[k]
        );
      }
      if (!Object.keys(ipList).length) {
        ipList = { COM: [""] };
      }

      for (var code in ipList) {
        for (var ip of ipList[code]) {
          finalConfigList = finalConfigList.concat(
            getMultipleRandomElements(
              vmessConfigList
                .map(decodeVmess)
                .map((cnf) => mixConfig(cnf, url, "vmess", ip, code))
                .filter((cnf) => !!cnf && cnf.id)
                .map(encodeVmess)
                .filter((cnf) => !!cnf),
              maxPerType
            )
          );
          if (myConfigs.length) {
            finalConfigList = finalConfigList.concat(
              myConfigs
                .map(decodeVmess)
                .map((cnf) => mixConfig(cnf, url, "vmess", ip, code))
                .filter((cnf) => !!cnf && cnf.id)
                .map(encodeVmess)
                .filter((cnf) => !!cnf)
            );
          }
        }
      }

      return new Response(btoa(finalConfigList.join("\n")));
    } else {
      var url = new URL(request.url);
      var newUrl = new URL("https://" + url.pathname.replace(/^\/|\/$/g, ""));
      return fetch(new Request(newUrl, request));
    }
  },
};

function encodeVmess(conf) {
  try {
    return "vmess://" + btoa(JSON.stringify(conf));
  } catch {
    return null;
  }
}

function decodeVmess(conf) {
  try {
    return JSON.parse(atob(conf.substr(8)));
  } catch {
    return {};
  }
}

function mixConfig(conf, url, protocol, ip, operator) {
  try {
    if (conf.tls != "tls") {
      return {};
    }
    var addr = conf.sni;
    if (!addr) {
      if (conf.add && !isIp(conf.add)) {
        addr = conf.add;
      } else if (conf.host && !isIp(conf.host)) {
        addr = conf.host;
      }
    }
    if (!addr) {
      return {};
    }
    const ops = {
      MKB: "Mokhaberat",
      IRC: "Irancell",
      MCI: "Hamrah Avval",
      RTL: "Rightel",
      MBT: "Mobin Net",
      HWB: "Highweb",
      AST: "Asiatech",
      PRS: "Pars Online",
      SHT: "Shatel",
      SHM: "Shatel Mobile",
      ZTL: "Zitel",
      ASK: "Andishe Sabz",
      RSP: "Raspina",
      AFN: "Afranet",
      PSM: "Pishgaman",
      ARX: "Arax",
      SMT: "Samantel",
      FNV: "Fanava",
      APT: "Aptel",
      DBN: "Dideban Net",
      OTH: "Other",
    };
    conf.name = (conf.name ? conf.name : conf.ps) + "-W-" + ops[operator];
    conf.ps = conf.name;
    conf.sni = url.hostname;
    if (ip) {
      conf.add = ip;
    } else {
      conf.add = addressList[Math.floor(Math.random() * addressList.length)];
    }

    if (protocol == "vmess") {
      conf.sni = url.hostname;
      conf.host = url.hostname;
      if (conf.path == undefined) {
        conf.path = "";
      }
      conf.path =
        "/" + addr + ":" + conf.port + "/" + conf.path.replace(/^\//g, "");
      conf.fp = fpList[Math.floor(Math.random() * fpList.length)];
      conf.alpn = alpnList[Math.floor(Math.random() * alpnList.length)];
      conf.port = conf.port;
    }
    return conf;
  } catch (e) {
    return {};
  }
}

function getMultipleRandomElements(arr, num) {
  var shuffled = [...arr].sort(() => 0.5 - Math.random());
  return shuffled.slice(0, num);
}

function isIp(str) {
  try {
    if (str == "" || str == undefined) return false;
    if (
      !/^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])(\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])){2}\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-4])$/.test(
        str
      )
    ) {
      return false;
    }
    var ls = str.split(".");
    if (ls == null || ls.length != 4 || ls[3] == "0" || parseInt(ls[3]) === 0) {
      return false;
    }
    return true;
  } catch (e) {}
  return false;
}

async function getJsonDataFromUrl(url) {
  const response = await fetch(url);
  const jsonData = await response.json();
  return jsonData;
}

async function fetchData() {
  try {
    const url =
      "https://raw.githubusercontent.com/vfarid/cf-clean-ips/main/list.json";
    const jsonData = await getJsonDataFromUrl(url);
    const ipv4 = jsonData["ipv4"];
    const ipSet = new Set();
    ipv4.forEach((element) => {
      const now = Date.now();
      const diff = now / 1000 - element["created_at"];
      const how_long = diff / (60 * 60 * 24);
      if (how_long < how_old) {
        if (!blacklist_provider.includes(element["provider"])) {
          if (whitelist_operator.includes(element["operator"])) {
            ipSet.add(element["ip"]);
          }
        }
      }
    });
    const ipList = Array.from(ipSet);
    const other_ips = ipList.slice(0, how_many);
    console.log(other_ips);
    return other_ips;
  } catch (error) {
    console.error(error);
  }
}
