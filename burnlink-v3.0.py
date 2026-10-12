#!/usr/bin/env python3
"""BurnLink 3.0 — portable one-time browser links. Python 3.10+, no pip packages.

Run: python burnlink.py   |   Local-only testing: python burnlink.py --local
The sender interface opens in your browser. Recipients only need a browser.
Keep this process and the PC running until pending links are opened or revoked.

Security boundary: BurnLink guarantees one successful retrieval from this process,
not one human viewing. Browser privacy controls are deterrents, not screenshot
prevention. Content visible or audible to a recipient can still be copied or
recorded. Encryption keys stay in URL fragments; passcodes are used locally to
wrap those keys and are not sent to the Python server as plain text. Cloudflare
provides the temporary public tunnel and can observe connection metadata.
"""
from __future__ import annotations

import argparse
import base64
import collections
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

VERSION = "3.0"
MAX_BODY = 30 * 1024 * 1024
MAX_CIPHER = 22 * 1024 * 1024
MAX_STORED = 192 * 1024 * 1024
ID_RE = re.compile(r"^[A-Za-z0-9_-]{32}$")

STYLE = r"""
:root{color-scheme:light;--canvas:#f4f4f5;--surface:#ffffff;--surface-2:#f8f8f9;--text:#1f2328;--muted:#66707a;--border:#d6d9dd;--border-strong:#b8bec5;--primary:#1769c2;--primary-hover:#11589f;--danger:#b42318;--danger-bg:#fff5f4;--success:#198754;--warn:#8a5a00;--shadow:0 1px 2px rgba(0,0,0,.04)}
@media(prefers-color-scheme:dark){:root{color-scheme:dark;--canvas:#18191b;--surface:#222427;--surface-2:#1d1f21;--text:#f1f3f5;--muted:#aab0b7;--border:#383b40;--border-strong:#50545a;--primary:#5ca8ff;--primary-hover:#82bdff;--danger:#ff766c;--danger-bg:#321f1f;--success:#58c48a;--warn:#e8bd68;--shadow:none}}
*{box-sizing:border-box}html{min-height:100%}body{margin:0;min-height:100vh;background:var(--canvas);color:var(--text);font:15px/1.5 "Segoe UI",system-ui,-apple-system,BlinkMacSystemFont,sans-serif;-webkit-font-smoothing:antialiased}
main{width:min(900px,100%);margin:0 auto;padding:36px 24px 64px}.app-header{display:flex;align-items:center;justify-content:space-between;padding-bottom:22px;border-bottom:1px solid var(--border);margin-bottom:30px}.brand{font-size:20px;font-weight:650;letter-spacing:-.35px}.version{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
h1{font-size:28px;line-height:1.2;letter-spacing:-.55px;margin:0 0 8px;font-weight:650}h2{font-size:18px;line-height:1.3;margin:0 0 18px;font-weight:650}h3{font-size:14px;margin:0 0 10px}p{margin:0 0 16px}.muted,small{color:var(--muted)}small{display:block;font-size:12.5px;line-height:1.45}.intro{margin-bottom:22px}.intro p{max-width:680px}.warning{border-left:3px solid var(--warn);padding:9px 12px;margin:18px 0 24px;background:var(--surface-2);color:var(--muted);font-size:13px}
.connection{background:var(--surface);border:1px solid var(--border);border-radius:9px;padding:14px 16px;margin-bottom:22px;box-shadow:var(--shadow)}.connection-head{display:flex;align-items:center;gap:9px;min-height:28px}.status-dot{width:9px;height:9px;border-radius:50%;background:var(--border-strong);flex:none}.status-dot.ready{background:var(--success)}.status-dot.bad{background:var(--danger)}.connection strong{font-size:14px}.connection p{margin:5px 0 0 18px;font-size:13px;color:var(--muted)}
.steps{display:grid;grid-template-columns:repeat(3,1fr);border-bottom:1px solid var(--border);margin:0 0 22px}.steps span{position:relative;padding:11px 4px 10px;color:var(--muted);font-size:13px}.steps span.on{color:var(--text);font-weight:600}.steps span.on:after{content:"";position:absolute;left:0;right:18px;bottom:-1px;height:2px;background:var(--primary)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:9px;padding:24px;box-shadow:var(--shadow);margin-bottom:18px}.section-label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:7px}.field-group{padding-top:3px}.divider{height:1px;background:var(--border);margin:22px 0}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.actions{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:26px}.actions-right{display:flex;gap:9px;margin-left:auto;flex-wrap:wrap}
label{display:block;font-weight:600;margin:16px 0 6px}input,textarea,select,button{font:inherit}input:not([type=checkbox]),textarea,select{width:100%;border:1px solid var(--border-strong);border-radius:6px;background:var(--surface);color:var(--text);padding:10px 11px;outline:none}input:not([type=checkbox]):focus,textarea:focus,select:focus{border-color:var(--primary);box-shadow:0 0 0 2px color-mix(in srgb,var(--primary) 20%,transparent)}textarea{min-height:180px;resize:vertical}input[type=file]{padding:8px}input[type=checkbox]{width:16px;height:16px;margin-top:2px;accent-color:var(--primary)}label.check{display:flex;gap:9px;align-items:flex-start;font-weight:400;padding:7px 0;margin:0}label.check span>small{margin-top:2px}
button{border:1px solid var(--primary);border-radius:6px;padding:9px 14px;background:var(--primary);color:#fff;font-weight:600;cursor:pointer;min-height:38px}button:hover:not(:disabled){background:var(--primary-hover);border-color:var(--primary-hover)}button.secondary{background:var(--surface);border-color:var(--border-strong);color:var(--text)}button.secondary:hover:not(:disabled){background:var(--surface-2);border-color:var(--border-strong)}button.danger{background:var(--surface);border-color:color-mix(in srgb,var(--danger) 55%,var(--border));color:var(--danger)}button.danger:hover:not(:disabled){background:var(--danger-bg);border-color:var(--danger)}button:disabled{opacity:.5;cursor:not-allowed}button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible,a:focus-visible,summary:focus-visible,[tabindex]:focus-visible{outline:2px solid var(--primary);outline-offset:2px}
.error{color:var(--danger);white-space:pre-wrap;margin:10px 0}.success{color:var(--success)}[hidden]{display:none!important}.subtle{border-top:1px solid var(--border);margin-top:20px;padding-top:14px}.subtle summary{cursor:pointer;font-weight:600;padding:5px 0}.subtle p{font-size:13px;color:var(--muted)}
#imagePreview{display:block;max-width:100%;max-height:220px;object-fit:contain;margin-top:12px;border:1px solid var(--border);border-radius:6px;background:var(--surface-2)}.media-box{margin-top:12px;padding:12px;border:1px solid var(--border);border-radius:7px;background:var(--surface-2)}.media-box audio{display:block;width:100%;margin-top:8px}.media-box .row{margin-top:8px}.song-start{max-width:220px}#shareLink{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;word-break:break-all}#history article{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:13px 0;border-top:1px solid var(--border)}#history article:first-child{border-top:0}#history article p{margin:0}#history article strong{font-size:13px}#history article button{padding:5px 10px;min-height:30px;font-size:12px}dl{display:grid;grid-template-columns:150px 1fr;gap:9px 16px;margin:0}dt{color:var(--muted)}dd{margin:0}dialog{width:min(780px,95vw);max-height:92vh;border:1px solid var(--border);border-radius:10px;background:var(--surface);color:var(--text);padding:20px;box-shadow:0 20px 60px #0004}dialog::backdrop{background:#0008}dialog iframe{width:100%;height:68vh;border:1px solid var(--border);border-radius:7px;background:var(--canvas)}
.viewer main{width:min(760px,100%);padding-top:32px}.viewer .app-header{margin-bottom:28px}.viewer .card{padding:26px}.viewer #gate{max-width:560px;margin:60px auto 0}.viewer #gate h1{font-size:26px}.viewer #open{width:100%;margin-top:8px}.viewer-note-head{display:flex;align-items:center;gap:12px;margin-bottom:10px}.viewer-note-head h1{font-size:22px;margin:0;flex:1}.viewer-note-head button{min-height:34px;padding:6px 10px}.timer{font-size:17px;font-weight:650;font-variant-numeric:tabular-nums;white-space:nowrap}
progress{display:block;width:100%;height:3px;accent-color:var(--primary);margin:0 0 16px}#frame{position:relative;max-height:62vh;min-height:180px;overflow:auto;background:var(--surface-2);border:1px solid var(--border);border-radius:7px;overscroll-behavior:contain;scrollbar-width:thin;touch-action:pan-y}#paper{min-height:100%;padding:22px;position:relative}#message{white-space:pre-wrap;overflow-wrap:anywhere;user-select:text;font-size:17px;line-height:1.65}#picture{display:block;max-width:100%;height:auto;margin-top:18px;border-radius:4px}.watermark{position:sticky;bottom:7px;pointer-events:none;text-align:right;font-size:10px;color:var(--muted);opacity:.55;padding-right:7px}.guarded #message,.guarded #picture{user-select:none;-webkit-user-select:none}
.protected #paper{user-select:none;visibility:hidden}.protected #message{user-select:none}.protected.revealing #paper{visibility:visible;clip-path:inset(var(--cut-top,0px) 0 var(--cut-bottom,0px) 0)}#frame.covered #paper{visibility:hidden!important}#frame.protected{touch-action:none}#hint{font-size:13px;color:var(--muted);margin:0 0 10px}.viewer-footnote{margin-top:10px}.privacy-screen{position:fixed;inset:0;background:#111214;z-index:100;display:grid;place-items:center;padding:24px;color:#fff}.privacy-screen>div{width:min(390px,100%);text-align:center}.privacy-screen h2{font-size:22px;margin-bottom:8px}.privacy-screen p{color:#bdc2c8}.privacy-screen .secondary{background:transparent;color:#fff;border-color:#6a6d73}body.obscured #reading{visibility:hidden}#spotifyArea,#audioArea{margin-top:18px}#audioArea audio{display:block;width:100%;margin-top:10px}#spotifyEmbed iframe{display:block;width:100%;height:152px;border:0;border-radius:7px;background:#111}#audioName,#viewerAudioName{overflow-wrap:anywhere}.music-note{margin-top:10px}.preview-banner{background:var(--surface-2);border-bottom:1px solid var(--border);text-align:center;padding:7px;font-size:12px;color:var(--muted)}a{color:var(--primary)}
@media(max-width:620px){main,.viewer main{padding:22px 14px 42px}.app-header{margin-bottom:22px}.card,.viewer .card{padding:18px}.grid{grid-template-columns:1fr;gap:0}.steps span{font-size:12px}.actions{align-items:stretch}.actions button{flex:1}.actions-right{width:100%}.actions-right button{flex:1}dl{grid-template-columns:105px 1fr}.viewer #gate{margin-top:28px}.viewer-note-head{align-items:flex-start;flex-wrap:wrap}.viewer-note-head h1{flex-basis:100%}#frame{max-height:58vh}.song-start{max-width:none}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
@media print{body>*{display:none!important}body:after{content:'BurnLink does not provide a printable view of this note.';display:block;padding:24px;color:#000;background:#fff}}
"""

COMMON_JS = r"""
'use strict';
const $=id=>document.getElementById(id);
function b64(bytes){let s='';for(let i=0;i<bytes.length;i+=32768)s+=String.fromCharCode(...bytes.subarray(i,i+32768));return btoa(s)}
function un64(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}
function url64(bytes){return b64(bytes).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')}
function unurl(s){return un64(s.replaceAll('-','+').replaceAll('_','/')+'='.repeat((4-s.length%4)%4))}
async function call(path,body,token){const headers={'Content-Type':'application/json','X-BurnLink':'1'};if(token)headers['X-Admin-Token']=token;const r=await fetch(path,{method:'POST',headers,body:JSON.stringify(body),cache:'no-store',credentials:'omit'});let d;try{d=await r.json()}catch{throw Error('The connection was interrupted. A note may already have been consumed.')}if(!r.ok)throw Error(d.error||'Request failed');return d}
async function passMaterial(password,salt){const raw=new TextEncoder().encode(password),base=await crypto.subtle.importKey('raw',raw,'PBKDF2',false,['deriveBits']);raw.fill(0);const bits=new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt,iterations:250000},base,512));const wrap=bits.slice(0,32),auth=bits.slice(32);bits.fill(0);return {wrap,auth}}
"""

SENDER_HTML = r"""
<main class="sender-shell">
<header class="app-header"><div class="brand">BurnLink</div><div class="version">3.0</div></header>
<section class="intro"><h1>New one-time link</h1><p class="muted">Write a message, add media if you want, then send the generated link. The recipient only needs a browser.</p></section>
<section class="connection"><div class="connection-head"><span id="connectionDot" class="status-dot"></span><strong id="connectionBadge">Checking connection</strong><span class="actions-right"><button id="connect" class="secondary" hidden>Start connection</button></span></div><p id="connectionText" role="status">Connecting to BurnLink…</p></section>
<div class="warning">Anything visible or audible can still be captured with another device. Browser privacy controls are deterrents, not a guarantee.</div>
<nav class="steps" aria-label="Create link progress"><span class="on" data-step="0">1&nbsp;&nbsp;Message</span><span data-step="1">2&nbsp;&nbsp;Options</span><span data-step="2">3&nbsp;&nbsp;Review</span></nav>
<section id="step0" class="card"><div class="section-label">Message</div><h2>What to send</h2>
<label for="text">Message</label><textarea id="text" maxlength="20000" placeholder="Write your message" autocomplete="off" spellcheck="false"></textarea><small><span id="count">0</span> / 20,000 characters. Drafts are not saved.</small>
<div class="divider"></div><div class="section-label">Optional media</div>
<label for="image">Image</label><input id="image" type="file" accept="image/png,image/jpeg,image/webp,image/gif"><small>PNG, JPEG, WebP, or GIF up to 8 MB. Images are resized and re-encoded before encryption.</small><img id="imagePreview" alt="Attachment preview" hidden><div class="row" style="margin-top:9px"><button class="secondary" id="removeImage" hidden>Remove image</button></div>
<label for="spotify">Spotify track</label><input id="spotify" type="url" inputmode="url" autocomplete="off" placeholder="https://open.spotify.com/track/…"><small>Paste a Spotify track link, or attach an audio file below. Use one or the other.</small>
<label for="audio">Audio file</label><input id="audio" type="file" accept="audio/mpeg,audio/mp3,audio/mp4,audio/x-m4a,audio/aac,audio/ogg,audio/wav,audio/webm"><small>MP3, M4A/AAC, OGG, WAV, or WebM up to 12 MB. Audio stays playable after the message itself closes.</small><div id="audioPreviewBox" class="media-box" hidden><strong id="audioName"></strong><audio id="audioPreview" controls preload="metadata"></audio><div class="row"><button class="secondary" id="removeAudio">Remove audio</button></div></div>
<label for="songStart">Start audio at</label><input id="songStart" class="song-start" type="text" inputmode="numeric" autocomplete="off" placeholder="1:23"><small>Optional. Enter seconds, M:SS, or H:MM:SS.</small>
<div class="actions"><span></span><button id="next0">Continue</button></div></section>
<section id="step1" class="card" hidden><div class="section-label">Delivery</div><h2>Link options</h2><div class="grid"><div><label for="seconds">Message stays visible for</label><select id="seconds"><option value="15">15 seconds</option><option value="30">30 seconds</option><option value="60" selected>1 minute</option><option value="120">2 minutes</option><option value="300">5 minutes</option><option value="600">10 minutes</option></select></div><div><label for="ttl">Unused link expires after</label><select id="ttl"><option value="300">5 minutes</option><option value="900">15 minutes</option><option value="3600">1 hour</option><option value="21600">6 hours</option><option value="86400" selected>24 hours</option><option value="172800">48 hours</option><option value="604800">7 days</option></select></div></div>
<label for="passcode">Passcode</label><input id="passcode" type="password" minlength="6" maxlength="128" autocomplete="new-password" placeholder="Optional"><div class="row" style="margin-top:8px"><button class="secondary" id="generatePasscode" type="button">Generate strong passcode</button><button class="secondary" id="togglePasscode" type="button">Show</button></div><small>If set, the passcode becomes a second encryption factor and is never sent to the BurnLink server as plain text. Send it separately.</small>
<div class="divider"></div><div class="section-label">Receipts & privacy</div>
<label class="check"><input id="notify" type="checkbox" checked><span>Notify me when the message is actually displayed<small>Link previews do not count. On Windows, BurnLink also attempts a native notification even if this sender tab is closed.</small></span></label>
<label class="check"><input id="guard" type="checkbox" checked><span>Privacy-sensitive shortcut guard<small>Detected Ctrl/Alt/Windows/Command, Print Screen, F12, copy, print, and similar actions hide the message. This cannot block every capture method.</small></span></label>
<label class="check"><input id="blur" type="checkbox" checked><span>Hide the message when the browser loses focus<small>The timer keeps running.</small></span></label>
<label class="check"><input id="watermark" type="checkbox" checked><span>Show a random session watermark<small>The watermark does not identify the recipient.</small></span></label>
<label class="check"><input id="spotlight" type="checkbox"><span>Hold-to-reveal mode<small>Advanced option. Only a narrow area is visible while the recipient holds the mouse or their finger.</small></span></label>
<div class="actions"><button class="secondary" id="back1">Back</button><button id="next1">Review</button></div></section>
<section id="step2" class="card" hidden><div class="section-label">Review</div><h2>Ready to create</h2><dl id="summary"></dl><div class="divider"></div><div class="row"><button class="secondary" id="preview">Preview recipient view</button><small>The preview never creates or consumes a link.</small></div><div class="actions"><button class="secondary" id="back2">Back</button><button id="create">Create link</button></div></section>
<section id="result" class="card" hidden><div class="section-label">Created</div><h2>Send this link</h2><label for="shareLink">Complete one-time link</label><input id="shareLink" readonly><div class="row" style="margin-top:12px"><button id="copy">Copy link</button><button class="secondary" id="save">Save as text</button><button class="danger" id="revoke">Revoke</button></div><p id="resultStatus" class="muted" role="status" style="margin-top:14px"></p><small>The part after # contains key material. Send the complete link. BurnLink does not recover a lost link.</small><div class="actions"><span></span><button class="secondary" id="another">Create another</button></div></section>
<p id="error" class="error" role="alert"></p>
<section class="card"><div class="section-label">Current run</div><h2>This session</h2><div id="history"><small>No links created yet.</small></div></section>
<details class="card subtle"><summary>Technical and privacy limits</summary><p>Message contents and attachments are encrypted in the sender browser with AES-256-GCM before storage. Encryption keys stay in the URL fragment. A passcode, when used, wraps the random message key locally with PBKDF2-derived AES-GCM key material; the server receives only a derived verifier for the five-attempt lockout.</p><p>The server keeps encrypted pending messages in memory. Restarting BurnLink invalidates pending links. Cloudflare provides the temporary public tunnel and can observe connection metadata. BurnLink is not an independently audited secure-messaging system.</p><p>The one-use guarantee applies to successful retrieval from this BurnLink process. Once a recipient can see or hear content, software cannot guarantee they did not photograph, record, save, or otherwise reproduce it.</p><p>Music intentionally outlives the message timer in the already-open recipient tab. Reloading or closing that tab ends access to attached audio; Spotify follows Spotify’s own playback behavior.</p></details>
<dialog id="previewDialog"><div class="row"><h2 style="flex:1;margin:0">Recipient preview</h2><button class="secondary" id="closePreview">Close</button></div><iframe id="previewFrame" title="Recipient preview"></iframe></dialog>
</main>
"""

SENDER_JS = r"""
let admin=location.hash.slice(1)||sessionStorage.getItem('burnlink-admin');
if(admin)sessionStorage.setItem('burnlink-admin',admin);history.replaceState(null,'',location.pathname);
let stage=0,imageData='',imageBusy=false,audioData='',audioName='',audioBusy=false,currentId='',serverState=null,pollBusy=false;
const labels={waiting:'Waiting',opened:'Opened — display not confirmed',viewed:'Viewed',expired:'Expired unopened',revoked:'Revoked',locked:'Disabled after five incorrect passcodes'};
let notifiedIds=new Set();try{notifiedIds=new Set(JSON.parse(localStorage.getItem('burnlink-notified')||'[]'))}catch{}
let notifyAudio=null;
function rememberNotified(id){notifiedIds.add(id);try{localStorage.setItem('burnlink-notified',JSON.stringify([...notifiedIds].slice(-300)))}catch{}}
function primeNotifyAudio(){try{notifyAudio=notifyAudio||new (window.AudioContext||window.webkitAudioContext)();if(notifyAudio.state==='suspended')notifyAudio.resume()}catch{}}
function ping(){try{primeNotifyAudio();if(!notifyAudio)return;const o=notifyAudio.createOscillator(),g=notifyAudio.createGain(),t=notifyAudio.currentTime;o.frequency.setValueAtTime(720,t);o.frequency.exponentialRampToValueAtTime(900,t+.1);g.gain.setValueAtTime(.0001,t);g.gain.exponentialRampToValueAtTime(.08,t+.012);g.gain.exponentialRampToValueAtTime(.0001,t+.22);o.connect(g);g.connect(notifyAudio.destination);o.start(t);o.stop(t+.23)}catch{}}
function notifyViewed(item){if(!item?.notify||item.state!=='viewed'||notifiedIds.has(item.id))return;rememberNotified(item.id);const when=new Date(item.updated*1000),msg='A BurnLink was viewed at '+when.toLocaleTimeString();document.title='Viewed — BurnLink';setTimeout(()=>{if(document.title==='Viewed — BurnLink')document.title='BurnLink'},12000);if(!serverState?.nativeNotify){ping();if('Notification'in window&&Notification.permission==='granted'){try{new Notification('BurnLink',{body:msg,tag:'burnlink-'+item.id,renotify:false})}catch{}}}}
function fail(e){$('error').textContent=e.message||String(e)}
function stageTo(n){stage=n;for(let i=0;i<3;i++)$('step'+i).hidden=i!==n;$('result').hidden=true;document.querySelectorAll('.steps [data-step]').forEach((x,i)=>x.classList.toggle('on',i===n));$('error').textContent='';window.scrollTo({top:0,behavior:'instant'})}
function spotifyTrack(value){const s=value.trim();if(!s)return '';let m=s.match(/^spotify:track:([A-Za-z0-9]{22})$/i);if(m)return 'https://open.spotify.com/track/'+m[1];let u;try{u=new URL(s)}catch{throw Error('Paste a Spotify track link.')}if(u.protocol!=='https:'||u.hostname!=='open.spotify.com')throw Error('Use an open.spotify.com track link.');const parts=u.pathname.split('/').filter(Boolean),i=parts.indexOf('track');if(i<0||!parts[i+1]||!/^[A-Za-z0-9]{22}$/.test(parts[i+1]))throw Error('That link is not a Spotify track.');return 'https://open.spotify.com/track/'+parts[i+1]}
function parseSongStart(value){const s=value.trim();if(!s)return 0;let total;if(/^\d+$/.test(s))total=Number(s);else{const parts=s.split(':');if(parts.length===2&&parts.every(x=>/^\d+$/.test(x))){const m=Number(parts[0]),q=Number(parts[1]);if(q>=60)throw Error('For M:SS, seconds must be below 60.');total=m*60+q}else if(parts.length===3&&parts.every(x=>/^\d+$/.test(x))){const h=Number(parts[0]),m=Number(parts[1]),q=Number(parts[2]);if(m>=60||q>=60)throw Error('For H:MM:SS, minutes and seconds must be below 60.');total=h*3600+m*60+q}else throw Error('Start time must look like 83, 1:23, or 1:02:03.')}if(!Number.isSafeInteger(total)||total<0||total>21600)throw Error('Start time must be between 0 and 6 hours.');return total}
function fmtSongStart(sec){const h=Math.floor(sec/3600),m=Math.floor((sec%3600)/60),q=sec%60;return h?h+':'+String(m).padStart(2,'0')+':'+String(q).padStart(2,'0'):m+':'+String(q).padStart(2,'0')}
function note(){return {text:$('text').value,image:imageData,spotify:spotifyTrack($('spotify').value),audio:audioData,audioName:audioName,startAt:parseSongStart($('songStart').value),seconds:Number($('seconds').value),guard:$('guard').checked,spotlight:$('spotlight').checked,blur:$('blur').checked,watermark:$('watermark').checked}}
function valid(){if(imageBusy)throw Error('Wait for the image to finish processing.');if(audioBusy)throw Error('Wait for the audio file to finish loading.');const spotify=spotifyTrack($('spotify').value),startAt=parseSongStart($('songStart').value);if(spotify&&audioData)throw Error('Choose either Spotify or an attached audio file, not both.');if(startAt&&!spotify&&!audioData)throw Error('Add audio before setting a start time.');if(!$('text').value.trim()&&!imageData&&!spotify&&!audioData)throw Error('Add a message, image, Spotify track, or audio file.');if(imageData.length+audioData.length>19*1024*1024)throw Error('The combined image and audio are too large.');const p=$('passcode').value;if(p&&p.length<6)throw Error('Use a passcode of at least 6 characters.')}
$('text').oninput=()=>{$('count').textContent=$('text').value.length};
$('removeImage').onclick=()=>{imageData='';$('image').value='';$('imagePreview').removeAttribute('src');$('imagePreview').hidden=true;$('removeImage').hidden=true};
$('image').onchange=async()=>{imageBusy=true;$('error').textContent='';imageData='';$('imagePreview').hidden=true;$('removeImage').hidden=true;let url;try{const f=$('image').files[0];if(!f)return;if(!['image/png','image/jpeg','image/webp','image/gif'].includes(f.type))throw Error('Choose a PNG, JPEG, WebP, or GIF image.');if(f.size>8*1024*1024)throw Error('Choose an image smaller than 8 MB.');url=URL.createObjectURL(f);const im=new Image();im.src=url;await im.decode();if(im.width*im.height>40000000)throw Error('Image dimensions are too large. Resize it first.');const scale=Math.min(1,2400/Math.max(im.width,im.height)),c=document.createElement('canvas');c.width=Math.max(1,Math.round(im.width*scale));c.height=Math.max(1,Math.round(im.height*scale));c.getContext('2d').drawImage(im,0,0,c.width,c.height);imageData=c.toDataURL(f.type==='image/png'?'image/png':'image/jpeg',.9);c.width=c.height=0;if(imageData.length>5*1024*1024){imageData='';throw Error('This image is still too large after processing. Choose a smaller image.')} $('imagePreview').src=imageData;$('imagePreview').hidden=false;$('removeImage').hidden=false}catch(e){$('image').value='';fail(e)}finally{if(url)URL.revokeObjectURL(url);imageBusy=false}};
$('removeAudio').onclick=()=>{audioData='';audioName='';$('audio').value='';$('audioPreview').pause();$('audioPreview').removeAttribute('src');$('audioPreview').load();$('audioName').textContent='';$('audioPreviewBox').hidden=true};
$('audio').onchange=async()=>{audioBusy=true;$('error').textContent='';$('removeAudio').click();try{const f=$('audio').files[0];if(!f)return;const ext=(f.name.split('.').pop()||'').toLowerCase(),types=['audio/mpeg','audio/mp3','audio/mp4','audio/x-m4a','audio/aac','audio/ogg','audio/wav','audio/webm'],exts=['mp3','m4a','aac','ogg','oga','wav','webm'];if(!types.includes(f.type)&&!exts.includes(ext))throw Error('Choose an MP3, M4A/AAC, OGG, WAV, or WebM audio file.');if(f.size>12*1024*1024)throw Error('Choose an audio file 12 MB or smaller.');audioData=await new Promise((resolve,reject)=>{const r=new FileReader();r.onload=()=>resolve(String(r.result));r.onerror=()=>reject(Error('Could not read that audio file.'));r.readAsDataURL(f)});if(!/^data:audio\/(mpeg|mp3|mp4|x-m4a|aac|ogg|wav|webm);base64,[A-Za-z0-9+/=]+$/i.test(audioData)){audioData='';throw Error('This browser could not identify the audio format safely. Try MP3 or M4A.')}audioName=f.name.slice(0,160);$('audioName').textContent=audioName;$('audioPreview').src=audioData;$('audioPreviewBox').hidden=false}catch(e){$('audio').value='';audioData='';audioName='';fail(e)}finally{audioBusy=false}};
$('generatePasscode').onclick=()=>{$('passcode').value=url64(crypto.getRandomValues(new Uint8Array(12)));$('passcode').dispatchEvent(new Event('input'))};$('togglePasscode').onclick=()=>{const show=$('passcode').type==='password';$('passcode').type=show?'text':'password';$('togglePasscode').textContent=show?'Hide':'Show'};
$('next0').onclick=()=>{try{valid();stageTo(1)}catch(e){fail(e)}};$('back1').onclick=()=>stageTo(0);$('back2').onclick=()=>stageTo(1);
$('next1').onclick=()=>{try{valid();const n=note(),music=n.spotify?'Spotify'+(n.startAt?' · '+fmtSongStart(n.startAt):''):(n.audio?'Attached audio'+(n.startAt?' · '+fmtSongStart(n.startAt):''):'None'),pairs=[['Message',n.text.length+' characters'+(n.image?' + image':'')],['Music',music],['Visible for',$('seconds').selectedOptions[0].text],['Unused expiry',$('ttl').selectedOptions[0].text],['Passcode',$('passcode').value?'Required':'None'],['View receipt',$('notify').checked?'On':'Off'],['Focus protection',n.blur?'On':'Off'],['Shortcut guard',n.guard?'On':'Off'],['Watermark',n.watermark?'On':'Off'],['Reveal mode',n.spotlight?'Hold-to-reveal':'Normal reading']];$('summary').replaceChildren();for(const [a,b]of pairs){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=a;dd.textContent=b;$('summary').append(dt,dd)}stageTo(2)}catch(e){fail(e)}};
$('connect').onclick=async()=>{try{$('connect').disabled=true;await call('/api/connect',{},admin);await poll()}catch(e){fail(e)}finally{$('connect').disabled=false}};
async function buildEncrypted(){const p=$('passcode').value,keyRaw=crypto.getRandomValues(new Uint8Array(32)),key=await crypto.subtle.importKey('raw',keyRaw,'AES-GCM',false,['encrypt']),iv=crypto.getRandomValues(new Uint8Array(12)),bytes=new TextEncoder().encode(JSON.stringify(note())),cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,bytes);bytes.fill(0);let fragment='3.'+url64(keyRaw),auth='';if(p){const salt=crypto.getRandomValues(new Uint8Array(16)),wrapIv=crypto.getRandomValues(new Uint8Array(12)),mat=await passMaterial(p,salt),wrapKey=await crypto.subtle.importKey('raw',mat.wrap,'AES-GCM',false,['encrypt']),wrapped=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:wrapIv},wrapKey,keyRaw));auth=url64(mat.auth);fragment='3p.'+url64(salt)+'.'+url64(wrapIv)+'.'+url64(wrapped);mat.wrap.fill(0);mat.auth.fill(0);wrapped.fill(0)}keyRaw.fill(0);return {cipher:b64(new Uint8Array(cipher)),iv:b64(iv),fragment,auth,passcode:!!p}}
$('create').onclick=async()=>{try{valid();if(!serverState?.ready)throw Error('Start the connection and wait until it is ready.');$('create').disabled=true;$('error').textContent='';if($('notify').checked&&!serverState?.nativeNotify){primeNotifyAudio();if('Notification'in window&&Notification.permission==='default'){try{await Notification.requestPermission()}catch{}}}const enc=await buildEncrypted(),d=await call('/api/create',{cipher:enc.cipher,iv:enc.iv,ttl:Number($('ttl').value),seconds:Number($('seconds').value),passcode:enc.passcode,auth:enc.auth,notify:$('notify').checked},admin);currentId=d.id;$('shareLink').value=d.url+'#'+enc.fragment;$('step2').hidden=true;$('result').hidden=false;$('revoke').disabled=false;$('text').value='';$('count').textContent='0';$('passcode').value='';$('passcode').type='password';$('togglePasscode').textContent='Show';$('spotify').value='';$('songStart').value='';$('removeImage').click();$('removeAudio').click();await poll()}catch(e){fail(e)}finally{$('create').disabled=false}};
$('copy').onclick=async()=>{try{await navigator.clipboard.writeText($('shareLink').value);$('copy').textContent='Copied';setTimeout(()=>$('copy').textContent='Copy link',1800)}catch{$('shareLink').select();fail(Error('Press Ctrl+C to copy the selected link.'))}};
$('save').onclick=()=>{const blob=new Blob(['BurnLink one-time link\r\n\r\n'+$('shareLink').value+'\r\n'],{type:'text/plain'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='BurnLink-link.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)};
async function revoke(id){try{await call('/api/revoke',{id},admin);await poll()}catch(e){fail(e)}}$('revoke').onclick=()=>revoke(currentId);$('another').onclick=()=>{currentId='';$('shareLink').value='';stageTo(0)};
function paintHistory(items){$('history').replaceChildren();if(!items.length){$('history').innerHTML='<small>No links created yet.</small>';return}for(const item of items){notifyViewed(item);const row=document.createElement('article'),p=document.createElement('p'),title=document.createElement('strong'),detail=document.createElement('small');title.textContent='Link '+item.id.slice(0,6)+' · '+(labels[item.state]||item.state);let detailText='Created '+new Date(item.created*1000).toLocaleTimeString()+' · expires '+new Date(item.expires*1000).toLocaleString();if(item.state==='viewed')detailText+=' · viewed '+new Date(item.updated*1000).toLocaleString();else if(item.state==='opened')detailText+=' · opened '+new Date(item.updated*1000).toLocaleString();detail.textContent=detailText;p.append(title,detail);row.append(p);if(item.state==='waiting'){const b=document.createElement('button');b.className='secondary';b.textContent='Revoke';b.onclick=()=>revoke(item.id);row.append(b)}$('history').append(row);if(item.id===currentId){$('resultStatus').textContent=item.state==='viewed'?'Viewed at '+new Date(item.updated*1000).toLocaleTimeString():item.state==='opened'?'Opened; waiting for display confirmation':item.state==='waiting'?'Waiting · expires '+new Date(item.expires*1000).toLocaleString():(labels[item.state]||item.state);$('revoke').disabled=item.state!=='waiting'}}}
async function poll(){if(pollBusy)return;pollBusy=true;try{serverState=await call('/api/status',{},admin);const ready=serverState.ready;$('connectionBadge').textContent=ready?(serverState.local?'Local test mode':'Ready'):serverState.state;$('connectionText').textContent=serverState.message;$('connectionDot').className='status-dot'+(ready?' ready':serverState.state==='Connection failed'?' bad':'');$('connect').hidden=ready||['starting','downloading','connecting'].includes(String(serverState.state).toLowerCase())||serverState.local;paintHistory(serverState.notes);$('create').disabled=!ready}catch(e){$('connectionBadge').textContent='Disconnected';$('connectionText').textContent='BurnLink is not responding. Keep the BurnLink window open.';$('connectionDot').className='status-dot bad';$('create').disabled=true;fail(e)}finally{pollBusy=false}}
$('preview').onclick=()=>{try{valid();$('previewFrame').src='/preview';$('previewDialog').showModal()}catch(e){fail(e)}};
window.addEventListener('message',e=>{if(e.origin===location.origin&&e.source===$('previewFrame').contentWindow&&e.data==='preview-ready')e.source.postMessage({type:'preview-note',note:note()},location.origin)});
function closePreview(){$('previewDialog').close();$('previewFrame').src='about:blank'}$('closePreview').onclick=closePreview;$('previewDialog').addEventListener('cancel',closePreview);
if(!crypto.subtle)fail(Error('Use a current Chrome, Edge, or Firefox browser. Browser encryption is unavailable.'));
poll();setInterval(poll,2500);
"""

VIEWER_HTML = r"""
<div id="previewBanner" class="preview-banner" hidden>Preview — this does not use a link</div>
<main><header class="app-header"><div class="brand">BurnLink</div></header>
<section id="gate" class="card"><h1>Private message</h1><p id="gateDescription" class="muted">Open it when you are ready. The timer starts when the message is displayed.</p><div id="passArea" hidden><label for="password">Passcode</label><input id="password" type="password" maxlength="128" autocomplete="off"><small>Five incorrect attempts disable this link.</small></div><p id="gateError" class="error" role="alert"></p><button id="open" disabled>Checking link…</button><small style="margin-top:12px">This link can be retrieved once.</small></section>
<section id="reading" class="card" hidden><div class="viewer-note-head"><h1>Private message</h1><span id="timer" class="timer" role="timer"></span><button class="secondary" id="burn">Close now</button></div><progress id="progress" max="1" value="1" aria-label="Time remaining"></progress><p id="hint"></p><div id="frame" tabindex="0" role="region" aria-label="Private message"><div id="paper"><div id="message"></div><img id="picture" alt="Image attached to this message" hidden></div><div id="watermark" class="watermark" hidden></div></div><small class="viewer-footnote">The message and image clear automatically. Any shared music remains available in this tab.</small></section>
<section id="gone" class="card" hidden><h1 id="goneTitle">Message closed</h1><p id="goneText" class="muted">The private message has been cleared.</p></section>
<section id="audioArea" class="card" hidden><div class="section-label">Audio</div><h2>Keep listening</h2><strong id="viewerAudioName">Audio attachment</strong><audio id="audioPlayer" controls preload="auto"></audio><small id="audioStartNote" class="music-note">This audio remains available until this tab is closed or reloaded.</small></section>
<section id="spotifyArea" class="card" hidden><div class="section-label">Spotify</div><h2>Keep listening</h2><p id="spotifyStatus" class="muted">Press play when you are ready.</p><div id="spotifyEmbed" aria-label="Spotify player"></div><div class="row" style="margin-top:10px"><a id="spotifyOpen" target="_blank" rel="noopener noreferrer">Open in Spotify</a></div><small class="music-note">The message timer does not remove this player.</small></section></main>
<div id="privacy" class="privacy-screen" role="dialog" aria-modal="true" aria-labelledby="privacyTitle" hidden><div><h2 id="privacyTitle">Message hidden</h2><p id="privacyText">The timer is still running.</p><div class="row" style="justify-content:center"><button id="resume">Continue</button><button id="hiddenClose" class="secondary">Close message</button></div></div></div>
"""

VIEWER_JS = r"""
const isPreview=location.pathname==='/preview',noteId=location.pathname.split('/').pop();
let keyText=location.hash.slice(1),linkParts=null,active=false,options=null,deadline=0,monoDeadline=0,ticker=null,holding=false,localY=90,lastPointer=null,opening=false,shielded=false,spotifyController=null,spotifyApiPromise=null;
const pressed=new Set(),frame=$('frame');
function wipe(title='Message closed',message=''){const keepMusic=!$('spotifyArea').hidden||!$('audioArea').hidden;active=false;holding=false;keyText='';linkParts=null;options=null;lastPointer=null;shielded=false;pressed.clear();clearInterval(ticker);document.body.classList.remove('obscured');$('privacy').hidden=true;$('reading').inert=false;$('message').replaceChildren();$('picture').removeAttribute('src');$('picture').hidden=true;$('password').value='';$('watermark').textContent='';frame.classList.remove('revealing','covered','protected','guarded');$('reading').hidden=true;$('gate').hidden=true;$('gone').hidden=false;$('goneTitle').textContent=title;$('goneText').textContent=message||(keepMusic?'The private message has been cleared. The music below is still available.':'The private message has been cleared. You can close this tab.')}
function left(){return Math.min(deadline-Date.now(),monoDeadline-performance.now())}
function tick(){if(!active)return;const ms=left();if(ms<=0){wipe('Time is up');return}const seconds=Math.ceil(ms/1000);$('timer').textContent=seconds+'s';$('progress').value=ms/(options.seconds*1000);if(shielded)$('privacyText').textContent=seconds+' seconds remain. The timer is still running.'}
function conceal(){holding=false;lastPointer=null;frame.classList.remove('revealing')}
function shield(){if(!active)return;conceal();shielded=true;document.body.classList.add('obscured');frame.classList.add('covered');$('privacy').hidden=false;$('reading').inert=true;tick()}
function resume(e){tick();if(!active||document.hidden||e.ctrlKey||e.altKey||e.metaKey||pressed.size)return;$('privacy').hidden=true;shielded=false;document.body.classList.remove('obscured');frame.classList.remove('covered');$('reading').inert=false;frame.focus({preventScroll:true})}
function strip(y){if(!active||shielded||left()<=0){tick();return}const p=$('paper');localY=Math.max(30,Math.min(frame.clientHeight-30,y));const center=frame.scrollTop+localY;frame.style.setProperty('--cut-top',Math.max(0,center-58)+'px');frame.style.setProperty('--cut-bottom',Math.max(0,p.offsetHeight-center-58)+'px')}
function reveal(y){if(!active||shielded||!options.spotlight||document.hidden)return;holding=true;strip(y);frame.classList.add('revealing')}
function spotifyFallback(url,startAt,why=''){$('spotifyEmbed').replaceChildren();const f=document.createElement('iframe');f.title='Spotify player';f.allow='autoplay; clipboard-write; encrypted-media; fullscreen; picture-in-picture';f.loading='eager';f.src='https://open.spotify.com/embed/track/'+url.split('/').pop()+'?utm_source=generator';$('spotifyEmbed').append(f);$('spotifyStatus').textContent=(startAt?'Requested start '+fmtSongTime(startAt)+'. ':'')+(why||'Press play when you are ready.')}
function spotifyApi(){if(spotifyApiPromise)return spotifyApiPromise;spotifyApiPromise=new Promise((resolve,reject)=>{let done=false;const finish=(fn,v)=>{if(done)return;done=true;clearTimeout(timer);fn(v)};window.onSpotifyIframeApiReady=api=>finish(resolve,api);const script=document.createElement('script');script.src='https://open.spotify.com/embed/iframe-api/v1';script.async=true;script.dataset.burnlinkSpotify='1';script.onerror=()=>finish(reject,Error('Spotify player API did not load.'));document.head.append(script);const timer=setTimeout(()=>finish(reject,Error('Spotify player API timed out.')),8000)});return spotifyApiPromise}
function fmtSongTime(sec){const h=Math.floor(sec/3600),m=Math.floor((sec%3600)/60),q=sec%60;return h?h+':'+String(m).padStart(2,'0')+':'+String(q).padStart(2,'0'):m+':'+String(q).padStart(2,'0')}
function showSpotify(url,startAt){$('spotifyArea').hidden=false;$('spotifyOpen').href=url;$('spotifyStatus').textContent=startAt?'Starts at '+fmtSongTime(startAt)+'. Press play when you are ready.':'Press play when you are ready.';const host=$('spotifyEmbed');host.replaceChildren();const target=document.createElement('div');host.append(target);spotifyApi().then(api=>{if($('spotifyArea').hidden)return;api.createController(target,{width:'100%',height:152,url},controller=>{spotifyController=controller;if(startAt){try{controller.loadEntity(url,false,startAt)}catch{spotifyFallback(url,startAt,'Spotify loaded without the requested start point.')}}})}).catch(()=>spotifyFallback(url,startAt,startAt?'Spotify loaded with the standard player; the requested start point may not be applied.':'Press play when you are ready.'))}
function showAudio(data,name,startAt){const player=$('audioPlayer');player.src=data;$('viewerAudioName').textContent=name||'Audio attachment';$('audioArea').hidden=false;$('audioStartNote').textContent=(startAt?'Starts at '+fmtSongTime(startAt)+'. ':'')+'This audio remains available until this tab is closed or reloaded.';if(startAt){const seek=()=>{try{const max=Number.isFinite(player.duration)&&player.duration>0?Math.max(0,player.duration-.05):startAt;player.currentTime=Math.min(startAt,max)}catch{}};if(player.readyState>=1)seek();else player.addEventListener('loadedmetadata',seek,{once:true})}}
function start(n,started=Date.now(),monoStarted=performance.now()){if(typeof n.text!=='string'||n.text.length>20000||!Number.isInteger(n.seconds)||n.seconds<15||n.seconds>600||typeof n.image!=='string'||(n.image&&!/^data:image\/(png|jpeg);base64,[A-Za-z0-9+/=]+$/.test(n.image))||typeof n.spotify!=='string'||(n.spotify&&!/^https:\/\/open\.spotify\.com\/track\/[A-Za-z0-9]{22}$/.test(n.spotify))||typeof n.audio!=='string'||(n.audio&&!/^data:audio\/(mpeg|mp3|mp4|x-m4a|aac|ogg|wav|webm);base64,[A-Za-z0-9+/=]+$/i.test(n.audio))||n.audio.length>17*1024*1024||typeof n.audioName!=='string'||n.audioName.length>160||!Number.isInteger(n.startAt)||n.startAt<0||n.startAt>21600||(n.spotify&&n.audio))throw Error('Invalid message format.');options={seconds:n.seconds,guard:n.guard!==false,spotlight:!!n.spotlight,blur:!!n.blur,watermark:!!n.watermark};deadline=started+n.seconds*1000;monoDeadline=monoStarted+n.seconds*1000;active=true;$('gate').hidden=true;$('gone').hidden=true;$('reading').hidden=false;$('message').textContent=n.text;if(n.image){$('picture').src=n.image;$('picture').hidden=false}if(n.audio)showAudio(n.audio,n.audioName,n.startAt);else $('audioArea').hidden=true;if(n.spotify)showSpotify(n.spotify,n.startAt);else $('spotifyArea').hidden=true;n.text='';n.image='';n.audio='';n.audioName='';n.spotify='';n.startAt=0;$('password').value='';frame.classList.toggle('protected',options.spotlight);frame.classList.toggle('guarded',options.guard);frame.scrollTop=0;frame.setAttribute('aria-label',options.spotlight?'Private message. Hold mouse or touch to reveal. Keyboard: hold Space; arrows move the reveal area.':'Private message. Scroll to read.');$('hint').hidden=!options.spotlight;$('hint').textContent=matchMedia('(pointer:coarse)').matches?'Hold your finger on the message to reveal it. Move near an edge to scroll.':'Hold the mouse button on the message to reveal it. Move near an edge to scroll.';$('watermark').hidden=!options.watermark;$('watermark').textContent='PRIVATE · '+url64(crypto.getRandomValues(new Uint8Array(6)))+' · '+new Date().toLocaleTimeString();window.scrollTo(0,0);frame.focus({preventScroll:true});tick();ticker=setInterval(tick,100);if(active&&options.blur&&(document.hidden||!document.hasFocus()))shield()}
function parseFragment(){const raw=keyText;if(/^3\.[A-Za-z0-9_-]{43}$/.test(raw))return {passcode:false,key:raw.slice(2)};const m=raw.match(/^3p\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{64})$/);if(m)return {passcode:true,salt:m[1],wrapIv:m[2],wrapped:m[3]};throw Error('The key is missing or incomplete. Ask the sender for the complete link, including the # part.')}
async function prepare(){try{if(!crypto.subtle)throw Error('Use a current Chrome, Edge, or Firefox browser.');linkParts=parseFragment();const r=await fetch('/api/info/'+noteId,{cache:'no-store',credentials:'omit'}),d=await r.json();if(!r.ok)throw Error(d.error);if(!!d.passcode!==!!linkParts.passcode)throw Error('This link is incomplete or does not match the message.');$('passArea').hidden=!d.passcode;$('gateDescription').textContent='Once opened, you have '+d.seconds+' seconds before the private message clears.';$('open').disabled=false;$('open').textContent='Open message'}catch(e){$('gateError').textContent=e.message;$('open').textContent='Unavailable'}}
async function unlockKey(){if(!linkParts.passcode){const raw=unurl(linkParts.key);return {raw,auth:''}}const mat=await passMaterial($('password').value,unurl(linkParts.salt)),wrapKey=await crypto.subtle.importKey('raw',mat.wrap,'AES-GCM',false,['decrypt']);let raw;try{raw=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:unurl(linkParts.wrapIv)},wrapKey,unurl(linkParts.wrapped)))}catch{raw=null}const auth=url64(mat.auth);mat.wrap.fill(0);mat.auth.fill(0);return {raw,auth}}
async function confirmViewed(receipt){for(const delay of [0,400,1200,2500]){if(delay)await new Promise(r=>setTimeout(r,delay));try{await call('/api/viewed/'+noteId,{receipt});return}catch{}}}
$('open').onclick=async()=>{if(opening)return;opening=true;$('open').disabled=true;$('gateError').textContent='';let consumed=false,receipt='';const begun=Date.now(),monoBegun=performance.now();try{if(linkParts?.passcode&&!$('password').value)throw Error('Enter the passcode.');const unlocked=await unlockKey(),d=await call('/api/open/'+noteId,{auth:unlocked.auth});consumed=true;receipt=d.receipt||'';if(!unlocked.raw)throw Error('Incorrect passcode.');const key=await crypto.subtle.importKey('raw',unlocked.raw,'AES-GCM',false,['decrypt']);unlocked.raw.fill(0);keyText='';linkParts=null;history.replaceState(null,'',location.pathname);const plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:un64(d.iv)},key,un64(d.cipher)));let n;try{n=JSON.parse(new TextDecoder().decode(plain))}finally{plain.fill(0)}start(n,begun,monoBegun);if(receipt)confirmViewed(receipt)}catch(e){if(consumed)wipe('Unable to display message','The one-use retrieval succeeded, but the message could not be decrypted or displayed. Ask the sender for a new link.');else{$('gateError').textContent=e.message;$('open').disabled=false}}finally{opening=false}};
$('password').addEventListener('keydown',e=>{if(e.key==='Enter'&&!$('open').disabled)$('open').click()});
frame.addEventListener('pointerdown',e=>{if(!active||shielded||!options.spotlight||e.button!==0)return;e.preventDefault();frame.focus({preventScroll:true});frame.setPointerCapture(e.pointerId);const r=frame.getBoundingClientRect(),point={y:e.clientY-r.top,touch:e.pointerType==='touch'};reveal(point.y-(point.touch?65:0));lastPointer=point});
frame.addEventListener('pointermove',e=>{if(!holding||shielded||!options?.spotlight)return;const r=frame.getBoundingClientRect();lastPointer={y:e.clientY-r.top,touch:e.pointerType==='touch'};strip(lastPointer.y-(lastPointer.touch?65:0))});
for(const type of ['pointerup','pointercancel','lostpointercapture'])frame.addEventListener(type,conceal);frame.addEventListener('scroll',()=>{if(holding)strip(localY)});setInterval(()=>{if(!active||shielded||!holding||!lastPointer)return;if(lastPointer.y<45)frame.scrollTop-=10;else if(lastPointer.y>frame.clientHeight-45)frame.scrollTop+=10;strip(localY)},35);
function sensitive(e){return e.ctrlKey||e.altKey||e.metaKey||['Control','Alt','Meta','OS','PrintScreen','F12'].includes(e.key)||e.code==='PrintScreen'}function modifier(e){return ['Control','Alt','Meta','OS'].includes(e.key)}
document.addEventListener('keydown',e=>{if(!active)return;if(e.key==='Escape'){e.preventDefault();wipe();return}if(options.guard&&sensitive(e)){if(modifier(e))pressed.add(e.code||e.key);shield();if(['PrintScreen','F12'].includes(e.key)||(e.ctrlKey||e.metaKey)&&['c','x','s','p','u','a'].includes(e.key.toLowerCase()))e.preventDefault();return}if(shielded)return;if(e.code==='Space'&&!e.target.closest('button,input,textarea,select,audio,a')){e.preventDefault();if(options.spotlight)reveal(localY)}if(options.spotlight&&['ArrowDown','ArrowUp'].includes(e.code)&&!e.target.closest('button,input,audio,a')){e.preventDefault();localY+=e.code==='ArrowDown'?22:-22;if(localY>frame.clientHeight-40){frame.scrollTop+=35;localY=frame.clientHeight-40}if(localY<40){frame.scrollTop-=35;localY=40}if(holding)strip(localY)}},true);
document.addEventListener('keyup',e=>{if(modifier(e))pressed.delete(e.code||e.key);if(!active)return;if(options.guard&&(e.key==='PrintScreen'||e.code==='PrintScreen')){e.preventDefault();shield()}if(e.code==='Space'&&!e.target.closest('button,input,textarea,select,audio,a')){e.preventDefault();conceal()}},true);
window.addEventListener('blur',()=>{conceal();pressed.clear();if(active&&options.blur)shield()});window.addEventListener('focus',()=>{pressed.clear();tick();if(active&&shielded)$('resume').focus({preventScroll:true})});document.addEventListener('visibilitychange',()=>{conceal();pressed.clear();tick();if(active&&options.blur&&document.hidden)shield()});window.addEventListener('pagehide',()=>{if(active)wipe()});window.addEventListener('pageshow',e=>{if(e.persisted)wipe()});window.addEventListener('beforeprint',()=>{if(active)shield()});
for(const type of ['copy','cut','contextmenu','dragstart','selectstart'])document.addEventListener(type,e=>{if(active&&options.guard){e.preventDefault();if(type!=='selectstart'&&type!=='dragstart')shield()}},true);
$('resume').onclick=resume;$('hiddenClose').onclick=()=>wipe();$('burn').onclick=()=>wipe();document.addEventListener('keydown',e=>{if(active&&shielded&&e.key==='Tab'){e.preventDefault();const next=document.activeElement===$('resume')?$('hiddenClose'):$('resume');next.focus({preventScroll:true})}},true);
if(isPreview){$('previewBanner').hidden=false;$('gate').hidden=true;window.addEventListener('message',e=>{if(e.origin===location.origin&&e.source===parent&&e.data?.type==='preview-note'){try{start(e.data.note)}catch(err){wipe('Preview error',err.message)}}});parent.postMessage('preview-ready',location.origin)}else prepare();
"""

def page(viewer=False):
    script = COMMON_JS + (VIEWER_JS if viewer else SENDER_JS)
    digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    html = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta name="referrer" content="no-referrer"><title>BurnLink</title>'
            '<link rel="icon" href="data:,"><style>' + STYLE + '</style></head><body class="' + ('viewer' if viewer else 'sender') + '">'
            + (VIEWER_HTML if viewer else SENDER_HTML) + '<script>' + script + '</script></body></html>')
    return html.encode(), digest

PAGES = {False: page(False), True: page(True)}


class Store:
    def __init__(self, on_viewed=None):
        self.lock = threading.RLock()
        self.notes = {}
        self.events = collections.OrderedDict()
        self.on_viewed = on_viewed

    def finish(self, nid, state):
        self.notes.pop(nid, None)
        if nid in self.events:
            self.events[nid]['state'] = state
            self.events[nid]['updated'] = time.time()
            self.events[nid].pop('_receipt', None)

    def clean(self):
        with self.lock:
            for nid, n in list(self.notes.items()):
                if time.monotonic() >= n['deadline']:
                    self.finish(nid, 'expired')
            while len(self.events) > 1000:
                old = next((k for k, v in self.events.items() if v['state'] != 'waiting'), None)
                if old is None:
                    break
                del self.events[old]

    def create(self, d):
        if not isinstance(d, dict):
            raise ValueError('Invalid message.')
        ttl, seconds = d.get('ttl'), d.get('seconds')
        if type(ttl) is not int or not 300 <= ttl <= 604800:
            raise ValueError('Expiry must be 5 minutes to 7 days.')
        if type(seconds) is not int or not 15 <= seconds <= 600:
            raise ValueError('Reading time must be 15 to 600 seconds.')
        protected = d.get('passcode', False)
        auth = d.get('auth', '')
        if type(protected) is not bool or not isinstance(auth, str):
            raise ValueError('Invalid passcode settings.')
        if protected:
            if not re.fullmatch(r'[A-Za-z0-9_-]{43}', auth):
                raise ValueError('Invalid passcode verifier.')
        elif auth:
            raise ValueError('Unexpected passcode verifier.')
        notify = d.get('notify', True)
        if type(notify) is not bool:
            raise ValueError('Notify setting must be true or false.')
        try:
            if not isinstance(d['cipher'], str) or not isinstance(d['iv'], str):
                raise ValueError()
            cipher = base64.b64decode(d['cipher'], validate=True)
            iv = base64.b64decode(d['iv'], validate=True)
        except (KeyError, ValueError, TypeError):
            raise ValueError('Invalid encrypted message.') from None
        if not 16 <= len(cipher) <= MAX_CIPHER or len(iv) != 12:
            raise ValueError('Invalid encrypted message size.')
        with self.lock:
            self.clean()
            if len(self.notes) >= 100 or sum(len(n['cipher']) for n in self.notes.values()) + len(cipher) > MAX_STORED:
                raise ValueError('Session is full. Revoke unused links first.')
            nid = secrets.token_urlsafe(24)
            now = time.time()
            self.notes[nid] = {'cipher': cipher, 'iv': iv, 'auth': auth if protected else '',
                               'attempts': 0, 'seconds': seconds, 'deadline': time.monotonic() + ttl}
            self.events[nid] = {'id': nid, 'state': 'waiting', 'created': now, 'expires': now + ttl,
                                'updated': now, 'notify': notify}
            return nid

    def info(self, nid):
        with self.lock:
            self.clean()
            n = self.notes.get(nid)
            return {'passcode': bool(n['auth']), 'seconds': n['seconds']} if n else None

    def consume(self, nid, auth):
        with self.lock:
            self.clean()
            n = self.notes.get(nid)
            if not n:
                return 410, {'error': 'This link is no longer available.'}
            if n['auth'] and not hmac.compare_digest(auth, n['auth']):
                n['attempts'] += 1
                remain = 5 - n['attempts']
                if not remain:
                    self.finish(nid, 'locked')
                    return 410, {'error': 'Five incorrect passcodes. This link is now disabled.'}
                return 403, {'error': f'Incorrect passcode. {remain} attempts remain.'}
            receipt = secrets.token_urlsafe(24)
            result = {'cipher': base64.b64encode(n['cipher']).decode(),
                      'iv': base64.b64encode(n['iv']).decode(), 'receipt': receipt}
            self.notes.pop(nid, None)  # Atomic one-use removal before any ciphertext is returned.
            event = self.events.get(nid)
            if event:
                event['state'] = 'opened'
                event['updated'] = time.time()
                event['_receipt'] = hashlib.sha256(receipt.encode('ascii')).digest()
            return 200, result

    def viewed(self, nid, receipt):
        callback_item = None
        with self.lock:
            event = self.events.get(nid)
            if not event or event.get('state') not in ('opened', 'viewed'):
                return False
            expected = event.get('_receipt')
            actual = hashlib.sha256(receipt.encode('ascii')).digest()
            if not expected or not hmac.compare_digest(expected, actual):
                return False
            if event['state'] != 'viewed':
                event['state'] = 'viewed'
                event['updated'] = time.time()
                event.pop('_receipt', None)
                callback_item = {k: v for k, v in event.items() if not k.startswith('_')}
        if callback_item and self.on_viewed:
            try:
                self.on_viewed(callback_item)
            except Exception:
                pass
        return True

    def status_items(self):
        with self.lock:
            self.clean()
            return [{k: v for k, v in item.items() if not k.startswith('_')}
                    for item in reversed(list(self.events.values()))][:100]


class LimitedServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, address, handler):
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(address, handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'BurnLink'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *_):
        pass  # Never write note URLs, passwords, or HTTP headers to logs.

    def send(self, status, payload, html=False, viewer=False):
        body = payload if html else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8' if html else 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Permitted-Cross-Domain-Policies', 'none')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('X-Robots-Tag', 'noindex, nofollow, noarchive')
        preview = self.server.admin and self.path == '/preview'
        self.send_header('X-Frame-Options', 'SAMEORIGIN' if preview else 'DENY')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
        if html:
            digest = PAGES[viewer][1]
            self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'sha256-" + digest +
                             "' https://open.spotify.com; style-src 'unsafe-inline'; img-src data: blob:; media-src data: blob:; connect-src 'self'; "
                             "frame-src 'self' https://open.spotify.com; frame-ancestors " + ("'self'" if preview else "'none'") +
                             "; base-uri 'none'; form-action 'none'; object-src 'none'")
        self.end_headers()
        if self.command != 'HEAD':
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, socket.timeout):
                pass

    def host_ok(self):
        host = self.headers.get('Host', '')
        own = f'127.0.0.1:{self.server.server_port}'
        return host == own or (not self.server.admin and host == self.server.app.public_host and bool(host))

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self.host_ok():
            return self.send(403, {'error': 'Invalid host.'})
        app = self.server.app
        if self.server.admin and self.path in ('/', '/preview'):
            viewer = self.path == '/preview'
            return self.send(200, PAGES[viewer][0], True, viewer)
        if not self.server.admin:
            if self.path == '/health':
                return self.send(200, {'instance': app.instance})
            if re.fullmatch(r'/n/[A-Za-z0-9_-]{32}', self.path):
                return self.send(200, PAGES[True][0], True, True)
            match = re.fullmatch(r'/api/info/([A-Za-z0-9_-]{32})', self.path)
            if match:
                data = app.store.info(match[1])
                return self.send(200 if data else 410, data or {'error': 'This note is no longer available.'})
        self.send(404, {'error': 'Not found.'})

    def do_POST(self):
        if not self.host_ok():
            return self.send(403, {'error': 'Invalid host.'})
        # Reject browser cross-origin requests and form submissions before reading a body.
        host = self.headers.get('Host', '')
        origin = self.headers.get('Origin')
        expected = ('http://' if host.startswith('127.0.0.1:') else 'https://') + host
        if (origin and origin != expected) or self.headers.get('X-BurnLink') != '1':
            return self.send(403, {'error': 'Open the original BurnLink page.'})
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
            return self.send(415, {'error': 'Expected JSON.'})
        app = self.server.app
        if self.server.admin and not hmac.compare_digest(self.headers.get('X-Admin-Token', ''), app.admin_token):
            return self.send(403, {'error': 'Reopen the sender address printed in the BurnLink window.'})
        limit = MAX_BODY if self.server.admin and self.path == '/api/create' else 2048
        try:
            if self.headers.get('Transfer-Encoding'):
                raise ValueError('Unsupported request encoding.')
            count = int(self.headers.get('Content-Length', '-1'))
            if not 0 <= count <= limit:
                return self.send(413, {'error': 'Request is too large.'})
            raw = self.rfile.read(count)
            if len(raw) != count:
                raise ValueError('Incomplete request.')
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError('Invalid request.')
        except (ValueError, UnicodeError, socket.timeout):
            return self.send(400, {'error': 'Invalid or incomplete request.'})
        if self.server.admin:
            if self.path == '/api/status':
                return self.send(200, app.status())
            if self.path == '/api/connect':
                app.connect()
                return self.send(200, {'ok': True})
            if self.path == '/api/create':
                if not app.ready:
                    return self.send(409, {'error': 'The public connection is not ready.'})
                try:
                    nid = app.store.create(data)
                except ValueError as e:
                    return self.send(400, {'error': str(e)})
                return self.send(200, {'id': nid, 'url': app.public_url + '/n/' + nid})
            if self.path == '/api/revoke':
                nid = data.get('id')
                if not isinstance(nid, str) or not ID_RE.fullmatch(nid):
                    return self.send(400, {'error': 'Invalid note ID.'})
                with app.store.lock:
                    if nid in app.store.notes:
                        app.store.finish(nid, 'revoked')
                return self.send(200, {'ok': True})
        else:
            match = re.fullmatch(r'/api/open/([A-Za-z0-9_-]{32})', self.path)
            if match:
                auth = data.get('auth', '')
                if not isinstance(auth, str) or (auth and not re.fullmatch(r'[A-Za-z0-9_-]{43}', auth)):
                    return self.send(400, {'error': 'Invalid passcode response.'})
                code, result = app.store.consume(match[1], auth)
                return self.send(code, result)
            match = re.fullmatch(r'/api/viewed/([A-Za-z0-9_-]{32})', self.path)
            if match:
                receipt = data.get('receipt', '')
                if not isinstance(receipt, str) or not re.fullmatch(r'[A-Za-z0-9_-]{32}', receipt):
                    return self.send(400, {'error': 'Invalid receipt.'})
                ok = app.store.viewed(match[1], receipt)
                return self.send(200 if ok else 409, {'ok': ok, 'error': None if ok else 'Receipt was not accepted.'})
        self.send(404, {'error': 'Not found.'})


def fetch_release():
    req = urllib.request.Request('https://api.github.com/repos/cloudflare/cloudflared/releases/latest',
                                 headers={'User-Agent': 'BurnLink/3.0', 'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def get_helper(update):
    system, machine = platform.system(), platform.machine().lower()
    if system == 'Windows':
        asset = 'cloudflared-windows-amd64.exe' if machine in ('amd64', 'x86_64', 'arm64', 'aarch64') else 'cloudflared-windows-386.exe'
        cache = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'BurnLink'
    elif system == 'Linux':
        arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(machine)
        if not arch:
            raise RuntimeError('Unsupported CPU. Supply an official helper with --cloudflared PATH.')
        asset = 'cloudflared-linux-' + arch
        cache = Path.home() / '.cache' / 'burnlink'
    else:
        raise RuntimeError('Automatic helper setup supports Windows and Linux. Use --cloudflared PATH on other systems.')
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / asset
    stamp = cache / (asset + '.sha256')
    cached_ok = False
    if destination.is_file() and stamp.is_file():
        try:
            saved = stamp.read_text(encoding='ascii').strip().lower()
            cached_ok = bool(re.fullmatch(r'[0-9a-f]{64}', saved)) and hashlib.sha256(destination.read_bytes()).hexdigest() == saved
        except OSError:
            cached_ok = False
    update('downloading', 'Checking the official Cloudflare helper release…')
    try:
        release = fetch_release()
    except (OSError, ValueError, urllib.error.URLError, urllib.error.HTTPError):
        if cached_ok:
            update('downloading', 'Using the previously verified tunnel helper…')
            return destination
        raise
    selected = next((a for a in release.get('assets', []) if a.get('name') == asset), None)
    if not selected:
        raise RuntimeError('The official release does not contain a compatible tunnel helper.')
    digest = selected.get('digest') or ''
    if not re.fullmatch(r'sha256:[0-9a-fA-F]{64}', digest):
        if cached_ok:
            update('downloading', 'Using the previously verified tunnel helper…')
            return destination
        raise RuntimeError('The official release has no SHA-256 asset digest. Download was stopped rather than running an unverified helper.')
    expected = digest.split(':')[1].lower()
    if destination.is_file() and hashlib.sha256(destination.read_bytes()).hexdigest() == expected:
        try:
            stamp.write_text(expected + '\n', encoding='ascii')
        except OSError:
            pass
        return destination
    url = selected['browser_download_url']
    if not url.startswith('https://github.com/cloudflare/cloudflared/releases/download/'):
        raise RuntimeError('Unexpected helper download source.')
    fd, temp_name = tempfile.mkstemp(prefix='download-', dir=cache)
    try:
        with os.fdopen(fd, 'wb') as out:
            req = urllib.request.Request(url, headers={'User-Agent': 'BurnLink/3.0'})
            with urllib.request.urlopen(req, timeout=45) as response:
                total = 0
                digest_obj = hashlib.sha256()
                while True:
                    block = response.read(256 * 1024)
                    if not block:
                        break
                    total += len(block)
                    if total > 150 * 1024 * 1024:
                        raise RuntimeError('Unexpected helper download size.')
                    digest_obj.update(block)
                    out.write(block)
                    update('downloading', f'Downloading the official tunnel helper: {total // (1024 * 1024)} MB…')
        if digest_obj.hexdigest() != expected:
            raise RuntimeError('Helper checksum mismatch. Nothing was run; try connecting again.')
        os.chmod(temp_name, 0o700)
        os.replace(temp_name, destination)
        try:
            stamp.write_text(expected + '\n', encoding='ascii')
        except OSError:
            pass
        return destination
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def windows_child_lifetime(proc):
    """Tie cloudflared to this process, even when the console X is clicked."""
    if os.name != 'nt':
        return lambda: None
    import ctypes
    from ctypes import wintypes

    class BasicLimits(ctypes.Structure):
        _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
                    ('flags', wintypes.DWORD), ('min_working', ctypes.c_size_t),
                    ('max_working', ctypes.c_size_t), ('active_limit', wintypes.DWORD),
                    ('affinity', ctypes.c_size_t), ('priority', wintypes.DWORD),
                    ('scheduling', wintypes.DWORD)]

    class IOCounts(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in
                    ('read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes')]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [('basic', BasicLimits), ('io', IOCounts),
                    ('process_memory', ctypes.c_size_t), ('job_memory', ctypes.c_size_t),
                    ('peak_process_memory', ctypes.c_size_t), ('peak_job_memory', ctypes.c_size_t)]

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise RuntimeError('Windows could not create the tunnel cleanup handle.')
    limits = ExtendedLimits()
    limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)) or not kernel.AssignProcessToJobObject(job, wintypes.HANDLE(int(proc._handle))):
        kernel.CloseHandle(job)
        raise RuntimeError('Windows could not attach automatic tunnel cleanup. No connection was kept open.')
    return lambda: kernel.CloseHandle(job)



def native_view_notification():
    if os.name != 'nt':
        return
    try:
        import winsound
        winsound.MessageBeep(winsound.MB_ICONASTERISK)
    except Exception:
        pass
    try:
        ps = ("Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; "
              "$n=New-Object System.Windows.Forms.NotifyIcon; $n.Icon=[System.Drawing.SystemIcons]::Information; "
              "$n.BalloonTipTitle='BurnLink'; $n.BalloonTipText='A one-time link was viewed.'; "
              "$n.Visible=$true; $n.ShowBalloonTip(5000); Start-Sleep -Seconds 6; $n.Dispose()")
        subprocess.Popen(['powershell.exe', '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', ps],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except Exception:
        pass


class App:
    def __init__(self, local=False, helper=None):
        self.local = local
        self.helper = helper
        self.admin_token = secrets.token_urlsafe(32)
        self.instance = secrets.token_urlsafe(20)
        self.store = Store(self.note_viewed)
        self.guard = threading.RLock()
        self.stop = threading.Event()
        self.ready = False
        self.state = 'Offline'
        self.message = 'Start a temporary connection when you are ready. No note is sent during setup.'
        self.public_host = ''
        self.public_url = ''
        self.proc = None
        self.worker = None
        self.temp = tempfile.TemporaryDirectory(prefix='burnlink-')
        self.servers = []
        for admin in (False, True):
            server = LimitedServer(('127.0.0.1', 0), Handler)
            server.admin = admin
            server.app = self
            self.servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        self.viewer, self.sender = self.servers
        self.sender_url = f'http://127.0.0.1:{self.sender.server_port}/#{self.admin_token}'
        if local:
            self.public_url = f'http://127.0.0.1:{self.viewer.server_port}'
            self.ready = True
            self.state = 'Local test only'
            self.message = 'Local test mode. These links work only on this computer; they cannot be sent to someone else.'
        threading.Thread(target=self.housekeeping, daemon=True).start()

    def note_viewed(self, item):
        if item.get('notify'):
            threading.Thread(target=native_view_notification, daemon=True).start()

    def housekeeping(self):
        while not self.stop.wait(1):
            self.store.clean()

    def update(self, state, message):
        with self.guard:
            self.state, self.message = state, message

    def status(self):
        self.store.clean()
        with self.guard:
            return {'ready': self.ready, 'local': self.local, 'state': self.state, 'message': self.message,
                    'nativeNotify': os.name == 'nt', 'notes': self.store.status_items()}

    def connect(self):
        with self.guard:
            if self.local or self.ready or (self.worker and self.worker.is_alive()):
                return
            # New tunnel -> new hostname; old pending links cannot be restored.
            with self.store.lock:
                for nid in list(self.store.notes):
                    self.store.finish(nid, 'revoked')
            self.update('starting', 'Starting the temporary connection…')
            self.worker = threading.Thread(target=self.tunnel, daemon=True)
            self.worker.start()

    def tunnel(self):
        proc = None
        close_job = lambda: None
        try:
            helper = Path(self.helper).expanduser().resolve() if self.helper else get_helper(self.update)
            if self.stop.is_set():
                return
            if not helper.is_file():
                raise RuntimeError('Tunnel helper was not found.')
            config = Path(self.temp.name) / 'config.yml'
            config.write_text('{}\n', encoding='utf-8')
            flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            proc = subprocess.Popen([str(helper), 'tunnel', '--config', str(config), '--no-autoupdate',
                                     '--protocol', 'http2', '--url', f'http://127.0.0.1:{self.viewer.server_port}'],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding='utf-8', errors='replace', creationflags=flags,
                                    cwd=self.temp.name)
            with self.guard:
                self.proc = proc
            close_job = windows_child_lifetime(proc)
            self.update('connecting', 'Waiting for the public connection. This can take about a minute…')
            found = threading.Event()
            tail = collections.deque(maxlen=4)

            def read_output():
                for line in proc.stdout:
                    # No raw tunnel logs in the sender UI; they can contain environment details.
                    match = re.search(r'https://([a-z0-9-]+\.trycloudflare\.com)\b', line)
                    if match and not found.is_set():
                        with self.guard:
                            self.public_host = match[1]
                            self.public_url = 'https://' + match[1]
                        found.set()
                    if 'ERR' in line:
                        tail.append('Cloudflare reported a connection error.')

            threading.Thread(target=read_output, daemon=True).start()
            until = time.monotonic() + 100
            while not self.stop.is_set() and time.monotonic() < until and proc.poll() is None:
                if found.wait(.3):
                    try:
                        req = urllib.request.Request(self.public_url + '/health', headers={'User-Agent': 'BurnLink/3.0'})
                        with urllib.request.urlopen(req, timeout=5) as response:
                            ok = json.load(response).get('instance') == self.instance
                        if ok:
                            with self.guard:
                                self.ready = True
                                self.state = 'Ready'
                                self.message = 'Connection checked. You can create links now. Keep BurnLink running and your PC awake.'
                            break
                    except (OSError, ValueError):
                        pass
                    self.stop.wait(2)
            if not self.ready and not self.stop.is_set():
                raise RuntimeError('Could not verify the public connection. Check Internet/firewall access and try Start private connection again. Existing Cloudflare settings are not changed.')
            while not self.stop.wait(1):
                if proc.poll() is not None:
                    raise RuntimeError('The tunnel stopped. Reconnect and create new links; old links will not be restored.')
        except Exception as exc:
            with self.guard:
                self.ready = False
            if isinstance(exc, urllib.error.HTTPError):
                reason = f'Download service returned HTTP {exc.code}. Wait and try connecting again.'
            elif isinstance(exc, urllib.error.URLError):
                reason = 'Could not reach the official download service. Check Internet access and try again.'
            else:
                reason = str(exc)
            self.update('Connection failed', reason)
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            if proc and proc.stdout:
                proc.stdout.close()
            close_job()

    def close(self):
        self.stop.set()
        with self.guard:
            self.ready = False
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
        with self.store.lock:
            self.store.notes.clear()
            self.store.events.clear()
        for server in self.servers:
            server.shutdown()
            server.server_close()
        if self.worker:
            self.worker.join(timeout=6)
        self.temp.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--local', '--no-tunnel', action='store_true', help='Local testing only; no download or public connection')
    parser.add_argument('--no-browser', action='store_true', help='Print the sender URL without opening a browser')
    parser.add_argument('--http2', action='store_true', help='Compatibility option: HTTP/2 is already the default')
    parser.add_argument('--cloudflared', metavar='PATH', help='Use your own trusted, official cloudflared binary')
    args = parser.parse_args()
    app = App(args.local, args.cloudflared)
    keep_awake = False
    if os.name == 'nt':
        try:
            import ctypes
            keep_awake = bool(ctypes.windll.kernel32.SetThreadExecutionState(0x80000001))
        except (AttributeError, OSError):
            pass
    print('\nBurnLink 3.0 — one-time links\n')
    print('Sender page (PRIVATE; do not share this address):\n' + app.sender_url)
    print('\nKeep this window open and your PC awake. Press Ctrl+C to stop.\n')
    if keep_awake:
        print('Automatic Windows sleep is paused while this program runs. Manual sleep still disconnects it.\n')
    if not args.no_browser:
        webbrowser.open(app.sender_url)
    try:
        while not app.stop.wait(1):
            pass
    except KeyboardInterrupt:
        print('\nClosing BurnLink. All pending notes are discarded.')
    finally:
        app.close()
        if keep_awake:
            ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)


if __name__ == '__main__':
    if sys.version_info < (3, 10):
        raise SystemExit('BurnLink needs Python 3.10 or newer from python.org.')
    main()
