#!/usr/bin/env python3
import ipaddress, json, socket, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PORTS = [22, 53, 80, 443, 445, 3389, 8080]
MAX_HOSTS = 256
TIMEOUT = 0.35
state = {"status":"idle","results":[],"network":"","ports":PORTS,"message":""}

def validate_network(value):
    net = ipaddress.ip_network(value, strict=False)
    if net.version != 4 or not net.is_private:
        raise ValueError("Only private IPv4 networks are allowed.")
    if net.num_addresses > MAX_HOSTS:
        raise ValueError("Maximum scan size is 256 addresses.")
    return net

def dns(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except Exception:
        return ""

def open_port(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        return s.connect_ex((str(ip), port)) == 0
    finally:
        s.close()

def scan_host(ip):
    ports = [p for p in PORTS if open_port(ip, p)]
    return {"ip": str(ip), "hostname": dns(ip), "ports": ports}

def run_scan(net):
    try:
        out = []
        with ThreadPoolExecutor(max_workers=32) as pool:
            jobs = [pool.submit(scan_host, ip) for ip in net.hosts()]
            for f in as_completed(jobs):
                r = f.result()
                if r["ports"]:
                    out.append(r)
        state["results"] = sorted(out, key=lambda r: tuple(map(int, r["ip"].split("."))))
        state["status"] = "done"
    except Exception as e:
        state["status"] = "error"
        state["message"] = str(e)

HTML = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Discovery</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#07111f;color:#e8eef7;font:15px Arial,sans-serif}
header{padding:34px 6vw;border-bottom:1px solid #28405c;background:linear-gradient(135deg,#0c2038,#07111f)}
h1{font-size:42px;margin:0}h1 span{color:#5eead4}
p{color:#9fb0c7;line-height:1.6}
main{width:min(1100px,92vw);margin:30px auto}
.card{background:#0d1b2d;border:1px solid #213751;border-radius:18px;padding:22px;margin-bottom:18px;box-shadow:0 12px 35px #0004}
form{display:flex;gap:12px;flex-wrap:wrap}
input{flex:1;min-width:230px;background:#07111f;color:#fff;border:1px solid #31506f;border-radius:10px;padding:14px}
button{border:0;border-radius:10px;padding:14px 20px;font-weight:800;cursor:pointer;background:#2dd4bf;color:#03201d}
.note{padding:12px;border-left:4px solid #fbbf24;background:#211c0d;color:#d8c58a;border-radius:8px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.stat{background:#091625;border:1px solid #20334a;border-radius:14px;padding:18px}
.stat b{font-size:25px;color:#5eead4;display:block;margin-top:5px}
table{width:100%;border-collapse:collapse;margin-top:18px}
th,td{padding:12px;border-bottom:1px solid #24384f;text-align:left}
th{color:#8fa6c0;font-size:13px}
.badge{display:inline-block;padding:5px 8px;border-radius:999px;background:#123f3a;color:#67f2d7;font-size:12px;margin:2px}
footer{text-align:center;color:#71859d;padding:25px}
@media(max-width:650px){.stats{grid-template-columns:1fr}h1{font-size:30px}}
</style>
</head>
<body>
<header>
<h1>Network <span>Discovery</span></h1>
<p>Local-network visibility dashboard. Scan only private networks you own or are authorized to assess.</p>
</header>
<main>
<div class="card">
<h2>Scan a private network</h2>
<form method="post" action="/scan">
<input name="network" placeholder="192.168.1.0/24" required>
<button>Start Discovery</button>
</form>
<p class="note">Safety limits: private IPv4 ranges only, maximum 256 addresses, and a small set of common TCP ports.</p>
</div>
<div class="card">
<h2>Results</h2>
<div id="results">Run a scan to see results.</div>
</div>
</main>
<footer>Network Discovery Dashboard · Python standard library · Authorized use only</footer>
<script>
const names={22:"SSH",53:"DNS",80:"HTTP",443:"HTTPS",445:"SMB",3389:"RDP",8080:"HTTP-alt"};
async function refresh(){
  let d=await (await fetch("/results")).json(),e=document.getElementById("results");
  if(d.status==="running"){e.innerHTML="<p>Scanning…</p>";setTimeout(refresh,700);return}
  if(d.status==="error"){e.innerHTML='<div class="note">'+d.message+"</div>";return}
  if(!d.results.length){e.innerHTML="<p>No responding services were found.</p>";return}
  let h='<div class="stats"><div class="stat">Hosts with services<b>'+d.results.length+'</b></div><div class="stat">Network<b>'+d.network+'</b></div><div class="stat">Ports checked<b>'+d.ports.join(", ")+'</b></div></div><table><tr><th>IP</th><th>Hostname</th><th>Services</th></tr>';
  for(const r of d.results){
    h+="<tr><td>"+r.ip+"</td><td>"+(r.hostname||"—")+"</td><td>"+r.ports.map(p=>'<span class="badge">'+(names[p]||"TCP")+" ("+p+")</span>").join("")+"</td></tr>"
  }
  e.innerHTML=h+"</table>"
}
refresh();
</script>
</body>
</html>"""

class Handler(BaseHTTPRequestHandler):
    def send(self, code, body, typ="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", typ)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self.send(200, HTML)
        elif path == "/results":
            self.send(200, json.dumps(state), "application/json")
        else:
            self.send(404, "Not found")

    def do_POST(self):
        if urlparse(self.path).path != "/scan":
            return self.send(404, "Not found")
        n = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()).get("network", [""])[0]
        try:
            net = validate_network(n)
        except Exception as e:
            state.update(status="error", message=str(e))
            return self.send(200, HTML)
        if state["status"] == "running":
            return self.send(200, HTML)
        state.update(status="running", network=str(net), results=[], message="")
        threading.Thread(target=run_scan, args=(net,), daemon=True).start()
        self.send(200, HTML)

    def log_message(self, *args):
        pass

if __name__ == "__main__":
    print("Open http://127.0.0.1:8000")
    ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
