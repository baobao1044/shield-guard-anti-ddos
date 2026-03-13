// ============================================================================
// Biometric SDK — Client-side behavioral analysis + server-side scoring
// Injects JS into responses to collect mouse, keyboard, scroll fingerprints
// ============================================================================

import { LRUCache } from '../utils/data-structures';
import { Logger } from '../utils/logger';

const log = new Logger('Biometric');

export interface BiometricConfig {
  enabled: boolean;
  injectIntoHTML: boolean;        // Auto-inject SDK into HTML responses
  scoreTTLMs: number;             // How long biometric score is cached (default: 1h)
  minEventsForScore: number;      // Min behavioral events to generate score (default: 5)
  humanThreshold: number;         // Score above this = likely human (default: 60)
}

export const DEFAULT_BIOMETRIC_CONFIG: BiometricConfig = {
  enabled: true,
  injectIntoHTML: true,
  scoreTTLMs: 3600000,
  minEventsForScore: 5,
  humanThreshold: 60,
};

interface BiometricData {
  mouseMovements: number;
  mouseJitter: number;
  avgMouseSpeed: number;
  keystrokes: number;
  avgKeystrokeInterval: number;
  scrollEvents: number;
  touchEvents: number;
  timeToInteract: number;
  screenRes: string;
  timezone: number;
  canvasHash: string;
  webglHash: string;
  installedFonts: number;
}

export class BiometricScorer {
  private readonly config: BiometricConfig;
  private scores: LRUCache<number>;

  private stats = {
    totalFingerprints: 0,
    avgHumanScore: 0,
    humansDetected: 0,
    botsDetected: 0,
  };

  constructor(config: BiometricConfig) {
    this.config = config;
    this.scores = new LRUCache(100000, config.scoreTTLMs);
  }

  /**
   * Score biometric data from client SDK (0-100, higher = more human)
   */
  score(ip: string, data: BiometricData): number {
    let humanScore = 0;

    // Mouse movement analysis (bots: no mouse or robotic straight lines)
    if (data.mouseMovements > 3) {
      humanScore += 15;
      if (data.mouseJitter > 0.5 && data.mouseJitter < 50) humanScore += 10;
      if (data.avgMouseSpeed > 10 && data.avgMouseSpeed < 5000) humanScore += 5;
    }

    // Keystroke dynamics (bots: no keystrokes or perfectly uniform timing)
    if (data.keystrokes > 0) {
      humanScore += 10;
      if (data.avgKeystrokeInterval > 30 && data.avgKeystrokeInterval < 500) humanScore += 10;
    }

    // Scroll behavior (humans scroll naturally)
    if (data.scrollEvents > 0) humanScore += 10;

    // Touch events on mobile
    if (data.touchEvents > 0) humanScore += 5;

    // Time to interact (bots interact instantly or not at all)
    if (data.timeToInteract > 200 && data.timeToInteract < 30000) humanScore += 10;
    else if (data.timeToInteract < 50) humanScore -= 10; // Suspiciously fast

    // Canvas/WebGL fingerprint (headless browsers sometimes lack these)
    if (data.canvasHash && data.canvasHash !== '0') humanScore += 5;
    if (data.webglHash && data.webglHash !== '0') humanScore += 5;

    // Screen resolution (headless: unusual sizes)
    if (data.screenRes) {
      const [w, h] = data.screenRes.split('x').map(Number);
      if (w >= 320 && w <= 7680 && h >= 240 && h <= 4320) humanScore += 5;
    }

    // Timezone (should be a reasonable value)
    if (data.timezone >= -720 && data.timezone <= 840) humanScore += 5;

    // Installed fonts (headless: often 0 or very few)
    if (data.installedFonts > 5) humanScore += 5;

    const clamped = Math.max(0, Math.min(100, humanScore));
    this.scores.set(ip, clamped);
    this.stats.totalFingerprints++;
    this.stats.avgHumanScore = this.stats.avgHumanScore * 0.95 + clamped * 0.05;
    if (clamped >= this.config.humanThreshold) this.stats.humansDetected++;
    else this.stats.botsDetected++;

    return clamped;
  }

  getScore(ip: string): number | null {
    return this.scores.get(ip) ?? null;
  }

  /**
   * Generate the client-side JavaScript SDK to inject into HTML responses
   */
  generateSDK(): string {
    return `<script>(function(){
var d={mm:0,mj:0,ms:0,ks:0,ki:0,sc:0,tc:0,tti:0,sr:screen.width+'x'+screen.height,tz:new Date().getTimezoneOffset(),ch:'0',wh:'0',ff:0};
var st=Date.now(),lx=0,ly=0,lt=0,kts=[];
document.addEventListener('mousemove',function(e){d.mm++;var dx=e.clientX-lx,dy=e.clientY-ly;var dist=Math.sqrt(dx*dx+dy*dy);var dt=e.timeStamp-lt;if(dt>0){d.ms=d.ms*0.9+(dist/dt*1000)*0.1;d.mj=d.mj*0.9+Math.abs(dist-d.ms*dt/1000)*0.1}lx=e.clientX;ly=e.clientY;lt=e.timeStamp});
document.addEventListener('keydown',function(){d.ks++;var n=Date.now();if(kts.length>0)d.ki=d.ki*0.8+(n-kts[kts.length-1])*0.2;kts.push(n);if(kts.length>20)kts.shift()});
document.addEventListener('scroll',function(){d.sc++});
document.addEventListener('touchstart',function(){d.tc++});
try{var c=document.createElement('canvas'),x=c.getContext('2d');if(x){x.textBaseline='top';x.font='14px Arial';x.fillText('fp',2,2);d.ch=c.toDataURL().slice(-16)}}catch(e){}
try{var g=document.createElement('canvas').getContext('webgl');if(g){var r=g.getExtension('WEBGL_debug_renderer_info');d.wh=r?g.getParameter(r.UNMASKED_RENDERER_WEBGL).slice(0,32):'1'}}catch(e){}
try{d.ff=document.fonts?document.fonts.size:0}catch(e){}
setTimeout(function(){d.tti=Date.now()-st;if(d.mm>2||d.ks>0||d.sc>0){var x=new XMLHttpRequest();x.open('POST','/shield-fp',true);x.setRequestHeader('Content-Type','application/json');x.send(JSON.stringify(d))}},5000);
})()</script>`;
  }

  getStats() { return { ...this.stats }; }
}
