package gledger

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"strings"
)

// Record is one parsed audit line. gledger owns the on-disk format, so it also
// owns reading it back — callers (replay tools, dashboards) reuse this instead of
// re-parsing the JSONL themselves.
type Record struct {
	TS      string `json:"ts"`
	TraceID string `json:"trace_id"`
	Service string `json:"service"`
	Span    string `json:"span"`
	Event   string `json:"event"`
	Fields  F      `json:"fields"`
	Prev    string `json:"prev"`
	Hash    string `json:"hash"`
}

// Read parses a hash-chained audit file into records, in file (chronological)
// order. It does not verify the chain — call VerifyFile for that.
func Read(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var recs []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 32<<20) // audit lines can be large (captured HTTP bodies)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r Record
		if json.Unmarshal([]byte(line), &r) == nil {
			recs = append(recs, r)
		}
	}
	return recs, sc.Err()
}

// RenderHTML builds a self-contained, dependency-free HTML page that plays a trace
// back one event at a time: a timeline on the left, an accumulating state panel on
// the right (findings as they are posted), with play / step / reset controls. It
// is generic — any gledger trace renders — and degrades gracefully when a trace
// has no findings or captures. verified is shown as the integrity banner.
func RenderHTML(title string, recs []Record, verified bool) ([]byte, error) {
	// Embed records with HTML escaping ON so any captured markup in field values
	// (e.g. an HTTP response body) cannot break out of the <script>.
	var jb bytes.Buffer
	enc := json.NewEncoder(&jb)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(recs); err != nil {
		return nil, err
	}
	badge := `<span class="ok">hash-chain verified</span>`
	if !verified {
		badge = `<span class="bad">INTEGRITY FAILED — not trustworthy</span>`
	}
	page := strings.NewReplacer(
		"__TITLE__", html.EscapeString(title),
		"__BADGE__", badge,
		"__COUNT__", fmt.Sprintf("%d", len(recs)),
		"__EVENTS__", jb.String(),
	).Replace(tmpl)
	return []byte(page), nil
}

const tmpl = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--mut:#8b949e;--acc:#58a6ff;--ok:#3fb950;--bad:#f85149;--warn:#d29922;--flag:#bc8cff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
header{padding:14px 18px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:center;flex-wrap:wrap}
h1{font-size:15px;margin:0;font-weight:600}
.ok{color:var(--ok)}.bad{color:var(--bad)}
.meta{color:var(--mut);font-size:12px}
.controls{display:flex;gap:8px;align-items:center;margin-left:auto;flex-wrap:wrap}
button{background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:6px 12px;cursor:pointer;font:inherit}
button:hover{border-color:var(--acc)}button:disabled{opacity:.4;cursor:default}
input[type=range]{accent-color:var(--acc)}
main{display:grid;grid-template-columns:1.6fr 1fr;gap:0;height:calc(100vh - 58px)}
@media(max-width:780px){main{grid-template-columns:1fr;height:auto}}
#timeline{overflow:auto;padding:12px 16px;border-right:1px solid var(--line)}
#side{overflow:auto;padding:12px 16px;background:var(--panel)}
.row{padding:6px 8px;border-left:3px solid var(--line);margin:4px 0;border-radius:0 4px 4px 0;opacity:.35;transition:opacity .15s}
.row.on{opacity:1}
.row .sp{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.04em}
.row .tx{white-space:pre-wrap;word-break:break-word}
.row.model{border-left-color:var(--acc)}
.row.tool{border-left-color:var(--warn)}
.row.board{border-left-color:var(--flag)}
.row.capture{border-left-color:var(--ok);background:rgba(63,185,80,.12)}
.row.contain{border-left-color:var(--bad)}
.row.role{border-left-color:#fff;margin-top:12px}
.row.role .tx{font-weight:700}
h2{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em;margin:0 0 8px}
.find{padding:5px 8px;border:1px solid var(--line);border-radius:6px;margin:5px 0;background:var(--bg)}
.ty{display:inline-block;font-size:10px;color:var(--bg);background:var(--flag);border-radius:4px;padding:1px 6px;margin-right:6px;vertical-align:middle}
.find .v{word-break:break-word}
#cap{margin-top:14px}
#capbox{padding:10px;border:1px solid var(--ok);border-radius:6px;background:rgba(63,185,80,.1);color:var(--ok);display:none}
.step{color:var(--mut);font-size:12px;min-width:92px;text-align:right}
</style></head>
<body>
<header>
  <h1>__TITLE__</h1>
  <span class="meta">__BADGE__ · __COUNT__ records · <span id="models"></span></span>
  <div class="controls">
    <button id="reset">⏮ reset</button>
    <button id="back">⏴ step</button>
    <button id="play">▶ play</button>
    <button id="fwd">step ⏵</button>
    <label class="meta">speed <input id="speed" type="range" min="120" max="1400" value="650" step="20"></label>
    <span class="step" id="counter"></span>
  </div>
</header>
<main>
  <div id="timeline"></div>
  <div id="side">
    <h2>Blackboard (findings as posted)</h2>
    <div id="board"></div>
    <div id="cap"><div id="capbox"></div></div>
    <h2 style="margin-top:16px">Current event</h2>
    <pre id="detail" class="meta" style="white-space:pre-wrap;word-break:break-word"></pre>
  </div>
</main>
<script>
const EVENTS = __EVENTS__;
const models = [...new Set(EVENTS.map(e=>e.fields&&e.fields.model).filter(Boolean))];
document.getElementById('models').textContent = models.length? ('models: '+models.join(', ')) : '';
const tl=document.getElementById('timeline'), board=document.getElementById('board'),
      capbox=document.getElementById('capbox'), detail=document.getElementById('detail'),
      counter=document.getElementById('counter');
let i=0, timer=null;
function cls(e){const k=e.event;
  if(e.span==='swarm'&&k==='role_start')return'role';
  if(k==='model_call')return'model';
  if(k==='tool_call'||k==='tool_result'||k==='repeat_skipped')return'tool';
  if(k==='finding')return'board';
  if(k==='capture_detected')return'capture';
  if(k==='egress_denied')return'contain';
  return'';}
function clip(s,n){s=(s||'').replace(/\s+/g,' ').trim();return s.length>n?s.slice(0,n)+'…':s;}
function line(e){const f=e.fields||{};
  switch(e.event){
    case'swarm_start':return'SWARM '+(f.swarm||'')+'  → target '+(f.target||'');
    case'run_start':return'RUN model='+(f.model||'')+'  skill='+(f.skill||'');
    case'role_start':return'▶ '+(f.role||'').toUpperCase()+' agent   (model='+(f.model||'')+', skill='+(f.skill||'')+')';
    case'egress_denied':return'⛔ off-target egress blocked: '+(f.beacon||'');
    case'model_call':return'🧠 '+(f.model||'model')+': '+clip(f.reply,160);
    case'parse_miss':return'… no valid tool call';
    case'repeat_skipped':return'↩ refused repeat of '+(f.tool||'');
    case'tool_call':return'→ '+(f.tool||'')+'  '+clip(JSON.stringify(f.args||{}),160);
    case'tool_result':return'⟵ '+clip(f.result,150);
    case'finding':return'📌 ['+(f.type||'')+'] '+clip(f.value,140);
    case'capture_detected':return'🚩 CAPTURE: '+(f.via||'');
    case'run_end':case'swarm_end':return'■ outcome='+(f.outcome||'')+(f.captured_via?('  via '+clip(f.captured_via,80)):'');
    default:return e.span+'/'+e.event;}}
function render(){
  tl.innerHTML=''; board.innerHTML=''; capbox.style.display='none';
  for(let j=0;j<EVENTS.length;j++){
    const e=EVENTS[j], d=document.createElement('div');
    d.className='row '+cls(e)+(j<i?' on':'');
    d.innerHTML='<span class="sp">['+e.span+'] '+e.event+'</span><div class="tx">'+esc(line(e))+'</div>';
    tl.appendChild(d);
    if(j<i){
      if(e.event==='finding'){const f=e.fields||{};const b=document.createElement('div');b.className='find';
        b.innerHTML='<span class="ty">'+esc(f.type||'')+'</span><span class="v">'+esc(clip(f.value,180))+'</span>';board.appendChild(b);}
      if(e.event==='capture_detected'){capbox.style.display='block';capbox.textContent='🚩 '+((e.fields||{}).via||'captured');}
    }
  }
  const cur=EVENTS[i-1];
  detail.textContent=cur?JSON.stringify(cur.fields||{},null,2):'(start)';
  counter.textContent=i+' / '+EVENTS.length;
  const on=tl.querySelectorAll('.row.on'); if(on.length)on[on.length-1].scrollIntoView({block:'nearest'});
  document.getElementById('back').disabled=i<=0;
  document.getElementById('fwd').disabled=i>=EVENTS.length;
}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML;}
function step(n){i=Math.max(0,Math.min(EVENTS.length,i+n));render();}
function stop(){if(timer){clearInterval(timer);timer=null;document.getElementById('play').textContent='▶ play';}}
document.getElementById('fwd').onclick=()=>{stop();step(1);};
document.getElementById('back').onclick=()=>{stop();step(-1);};
document.getElementById('reset').onclick=()=>{stop();i=0;render();};
document.getElementById('play').onclick=function(){
  if(timer){stop();return;}
  if(i>=EVENTS.length)i=0;
  this.textContent='⏸ pause';
  const sp=+document.getElementById('speed').value;
  timer=setInterval(()=>{if(i>=EVENTS.length){stop();return;}step(1);},sp);
};
render();
</script>
</body></html>`
