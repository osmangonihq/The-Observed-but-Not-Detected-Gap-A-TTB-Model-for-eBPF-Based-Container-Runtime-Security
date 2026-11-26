"""Regenerate all 7 figures with NO in-image titles (captions are authoritative)."""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.patches as patches
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
R = ROOT / 'experiments' / 'results'
OUT = ROOT / 'figures'; OUT.mkdir(parents=True, exist_ok=True)

data = json.loads((R/'audit.json').read_text())
DIFF = json.loads((R/'differential.json').read_text())
ABL = json.loads((R/'ablation.json').read_text())
tools = ["Falco", "Tetragon", "Tracee"]
verdicts = data["tools"]["Falco"]["techniques"]
tech_ids=[v["id"] for v in verdicts]; tech_names=[v["name"] for v in verdicts]

def fig1():
    fig=plt.figure(figsize=(13.5,9.2))
    gs=fig.add_gridspec(2,1,height_ratios=[1,0.92],hspace=0.32)
    def box(ax,x,y,w,h,text,fc,fs=9.3):
        ax.add_patch(patches.FancyBboxPatch((x,y),w,h,boxstyle="round,pad=0.02,rounding_size=0.08",linewidth=1.4,edgecolor="#22303f",facecolor=fc,zorder=2))
        ax.text(x+w/2,y+h/2,text,ha="center",va="center",fontsize=fs,color="#14202c",linespacing=1.3,zorder=3)
    def arrow(ax,x1,y1,x2,y2,color="#22303f",lw=1.6):
        ax.add_patch(patches.FancyArrowPatch((x1,y1),(x2,y2),arrowstyle="-|>",mutation_scale=13,linewidth=lw,color=color,shrinkA=2,shrinkB=2,zorder=1))
    ax=fig.add_subplot(gs[0]); ax.set_xlim(0,13.5); ax.set_ylim(0,6.5); ax.axis("off")
    ax.text(0.1,6.2,"(a) Detection-Trust Boundary",fontsize=11,fontweight="bold",color="#1f4e79")
    y=4.15
    box(ax,0.25,y,2.75,1.35,"KERNEL EVENT\nescape syscall / LSM hook\n(e.g. write to release_agent)","#dbeafe")
    box(ax,3.55,y,2.75,1.35,"OBSERVATION  O(e)\neBPF kprobe / tracepoint / LSM","#dcfce7")
    box(ax,6.85,y,2.75,1.35,"POLICY DECISION  P(e)\ncondition over event fields\n+ metadata + telemetry state","#fef9c3")
    box(ax,10.35,4.75,2.5,0.8,"ALERT   D(e)=1","#bbf7d0",fs=10)
    box(ax,10.35,3.65,2.5,0.8,"NO ALERT   D(e)=0","#fecaca",fs=10)
    arrow(ax,3.0,y+.68,3.55,y+.68); arrow(ax,6.3,y+.68,6.85,y+.68)
    arrow(ax,9.6,y+.9,10.35,5.15); arrow(ax,9.6,y+.42,10.35,4.05,color="#b91c1c")
    box(ax,0.25,1.85,2.75,1.1,"ATTACKER\nprivileged in-container workload","#fee2e2")
    arrow(ax,1.62,2.95,1.62,y)
    box(ax,6.45,1.4,3.85,1.6,"TRUST ANCHORS (delegated inputs)\nTB-01 privilege   TB-02 allowlists\nTB-03 telemetry   TB-04 names\nTB-05 cross-layer   TB-06 snapshots","#ffe4e6",fs=8.8)
    arrow(ax,8.37,3.0,8.37,y)
    ax.text(6.6,0.5,"GAP: O(e)=1 but P(e)=0 because P trusts an anchor the attacker can invalidate",ha="center",fontsize=9,fontweight="bold",color="#991b1b")
    ax=fig.add_subplot(gs[1]); ax.set_xlim(0,13.5); ax.set_ylim(0,5.6); ax.axis("off")
    ax.text(0.1,5.3,"(b) DTB-Audit pipeline",fontsize=11,fontweight="bold",color="#1f4e79")
    stages=[(0.2,"INPUT\nFalco / Tetragon\n/ Tracee policies","#dbeafe"),(2.9,"PARSE\nYAML + macro\nexpansion","#dcfce7"),(5.6,"NORMALISE\ncommon observable\nvocabulary","#fef9c3"),(8.3,"CHECK\n6 trust-anchor\nchecks","#ffe4e6"),(11.0,"SCORE\nTDS -> verdict\n+ reports","#e0e7ff")]
    for x,t,c in stages: box(ax,x,2.4,2.2,1.6,t,c,fs=8.8)
    for i in range(4): arrow(ax,stages[i][0]+2.2,3.2,stages[i+1][0],3.2)
    box(ax,4.4,0.35,4.8,1.0,"25-technique corpus -> coverage matrix, gap ratio, Wilson 95% CIs","#f3f4f6",fs=8.8)
    arrow(ax,10.1,2.4,8.0,1.35,color="#6b7280",lw=1.3)
    ax.text(6.7,4.65,"Every finding cites a literal policy fragment; all rates are reproducible from checked-in inputs.",ha="center",fontsize=8.6,color="#4b5563")
    fig.savefig(OUT/"fig1_dtb_model.png",dpi=300,bbox_inches="tight"); plt.close(fig)
def fig2():
    lm={"detected":2,"observed-not-detected":1,"no-rule":0}
    colors=["#e5e7eb","#f59e0b","#16a34a"]; cmap=ListedColormap(colors)
    m=np.zeros((len(verdicts),3),dtype=int)
    for ti,t in enumerate(tools):
        tv={v["id"]:v for v in data["tools"][t]["techniques"]}
        for ri,tid in enumerate(tech_ids): m[ri,ti]=lm[tv[tid]["classification"]]
    fig,ax=plt.subplots(figsize=(8.2,11)); ax.imshow(m,cmap=cmap,vmin=0,vmax=2,aspect='auto')
    ax.set_xticks(range(3)); ax.set_xticklabels(tools,fontsize=12,fontweight='bold')
    ax.set_yticks(range(len(tech_ids))); ax.set_yticklabels([f"{i}  {n}" for i,n in zip(tech_ids,tech_names)],fontsize=9)
    for r in range(len(tech_ids)):
        for c in range(3):
            ax.text(c,r,{0:'—',1:'GAP',2:'OK'}[m[r,c]],ha='center',va='center',color='white' if m[r,c] else '#6b7280',fontweight='bold',fontsize=10)
    ax.set_xticks(np.arange(-.5,3,1),minor=True); ax.set_yticks(np.arange(-.5,len(tech_ids),1),minor=True)
    ax.grid(which='minor',color='white',linewidth=2); ax.tick_params(which='minor',bottom=False,left=False)
    for s in ax.spines.values(): s.set_visible(False)
    fig.tight_layout(); fig.savefig(OUT/'fig2_coverage_heatmap.png',dpi=300,bbox_inches='tight'); plt.close(fig)

def fig3():
    classes=["privilege-attribute","identity-allowlist","telemetry-state","signature-name","cross-layer","temporal-scope"]
    pretty=["Privilege\nattribute","Identity\nallowlist","Telemetry\nstate","Signature\nname","Cross-layer\n(TOCTOU)","Temporal\nsnapshot"]
    series={t:[data["tools"][t]["trust_class_counts"].get(c,0) for c in classes] for t in tools}
    x=np.arange(6); w=0.26
    fig,ax=plt.subplots(figsize=(10.5,4.9))
    for i,t in enumerate(tools):
        bars=ax.bar(x+(i-1)*w,series[t],width=w,label=t,edgecolor="#22303f",linewidth=0.8)
        for b in bars: ax.text(b.get_x()+b.get_width()/2,b.get_height()+0.3,f"{int(b.get_height())}",ha='center',va='bottom',fontsize=8)
    ax.set_xticks(x); ax.set_xticklabels(pretty,fontsize=9); ax.set_ylabel("Findings in audited policy files",fontsize=10)
    ax.legend(fontsize=10); ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False); ax.grid(axis='y',alpha=.25)
    fig.tight_layout(); fig.savefig(OUT/'fig3_trust_anchors.png',dpi=300,bbox_inches='tight'); plt.close(fig)

def fig4():
    order=["baseline","stale-capability","post-exec-privilege","renamed-binary","missing-parent","allowlisted-image","toctou-mismatch"]
    pretty=["baseline","stale\ncapability","post-exec\nprivilege","renamed\nbinary","missing\nparent","allowlisted\nimage","TOCTOU\nmismatch"]
    x=np.arange(7); w=.26
    fig,ax=plt.subplots(figsize=(12,5.1))
    for i,t in enumerate(tools):
        rates=[DIFF["tools"][t]["by_variant"][v]["rate"] for v in order]
        bars=ax.bar(x+(i-1)*w,rates,width=w,label=t,color=["#1f77b4","#ff7f0e","#2ca02c"][i],edgecolor="#22303f",linewidth=.7)
        for b in bars: ax.text(b.get_x()+b.get_width()/2,b.get_height()+.012,f"{b.get_height():.0%}",ha='center',va='bottom',fontsize=7.5)
    ax.set_xticks(x); ax.set_xticklabels(pretty,fontsize=9); ax.set_ylabel("Fraction of events that fire an alert",fontsize=10); ax.set_ylim(0,1.08)
    ax.legend(fontsize=10); ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False); ax.grid(axis='y',alpha=.25)
    fig.tight_layout(); fig.savefig(OUT/'fig4_detection_by_variant.png',dpi=300,bbox_inches='tight'); plt.close(fig)

def fig5():
    anchors=["stale-capability","post-exec-privilege","renamed-binary","missing-parent","allowlisted-image","toctou-mismatch"]
    pretty=["Stale capability\n(TB-01)","Post-exec privilege\n(TB-06)","Renamed binary\n(TB-04)","Missing parent\n(TB-03)","Allowlisted image\n(TB-02)","TOCTOU mismatch\n(TB-05)"]
    matrix=np.array([[DIFF["tools"][t]["anchor_drop"][a] for a in anchors] for t in tools])
    fig,ax=plt.subplots(figsize=(10,3.8)); im=ax.imshow(matrix,cmap="OrRd",vmin=0,vmax=.65,aspect='auto')
    ax.set_xticks(range(6)); ax.set_xticklabels(pretty,fontsize=9); ax.set_yticks(range(3)); ax.set_yticklabels(tools,fontsize=11,fontweight='bold')
    for r in range(3):
        for c in range(6):
            v=matrix[r,c]; ax.text(c,r,f"{v:.0%}",ha='center',va='center',color='white' if v>.35 else '#111827',fontweight='bold',fontsize=10)
    fig.colorbar(im,ax=ax,label="absolute recall drop",shrink=.85)
    fig.tight_layout(); fig.savefig(OUT/'fig5_anchor_drop.png',dpi=300,bbox_inches='tight'); plt.close(fig)


def fig7_leadtime():
    import numpy as np
    import json
    L = json.loads((R / 'lead_time.json').read_text())
    names = ['S02 core','S04 modprobe','S06 setns','S08 bpf','S10 environ','S12 mem']
    vals = [L['lead_ms'][k] for k in ['S02_renamed_core','S04_renamed_modprobe','S06_renamed_setns','S08_renamed_bpf','S10_renamed_environ','S12_renamed_mem']]
    fig, ax = plt.subplots(figsize=(10,4.2))
    bars = ax.bar(names, vals, color='#f59e0b', edgecolor='#22303f', linewidth=0.8)
    for b,v in zip(bars, vals):
        ax.text(b.get_x()+b.get_width()/2, v+0.6, f'{v:.1f}', ha='center', va='bottom', fontsize=9)
    ax.axhline(np.median(vals), color='#b91c1c', linestyle='--', linewidth=1.2, label=f'median {np.median(vals):.1f} ms')
    ax.set_ylabel('Alarm lead time (ms)', fontsize=10); ax.set_ylim(0, max(vals)*1.25)
    ax.legend(fontsize=9); ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
    ax.grid(axis='y', alpha=0.25); fig.tight_layout()
    fig.savefig(OUT/'fig7_leadtime.png', dpi=300, bbox_inches='tight'); plt.close(fig)

def fig8_ablation():
    th=ABL["thresholds"]; fig,ax=plt.subplots(figsize=(8.5,4.5))
    for t,color in zip(tools,["#1f77b4","#ff7f0e","#2ca02c"]):
        vals=[ABL["tools"][t][str(x)]["gap_ratio"] for x in th]
        ax.plot(th,vals,marker='o',label=t,color=color,linewidth=2)
    ax.set_xlabel("TDS robustness threshold",fontsize=10); ax.set_ylabel("Gap ratio",fontsize=10); ax.set_ylim(0,1)
    ax.legend(fontsize=10); ax.grid(alpha=.3); fig.tight_layout()
    fig.savefig(OUT/'fig8_ablation.png',dpi=300,bbox_inches='tight'); plt.close(fig)

def fig6_snapshot():
    fig,ax=plt.subplots(figsize=(13,5.4)); ax.set_xlim(0,13); ax.set_ylim(0,5.4); ax.axis('off')
    ax.add_patch(patches.FancyBboxPatch((.2,.55),5.0,4.0,boxstyle="round,pad=0.02,rounding_size=0.06",linewidth=1.4,edgecolor="#22303f",facecolor="#111827"))
    ax.add_patch(patches.FancyBboxPatch((5.5,.55),7.3,4.0,boxstyle="round,pad=0.02,rounding_size=0.06",linewidth=1.4,edgecolor="#22303f",facecolor="#111827"))
    mono="DejaVu Sans Mono"
    ax.text(.4,4.2,"$ kubectl logs ttb-suid-race",color="#22c55e",fontsize=9,fontfamily=mono)
    for i,l in enumerate(["SUID_AT_EXEC uid=1000 euid=0","SUID_AFTER_SETUID uid=0 euid=0","SUID_WRITE_DONE"]):
        ax.text(.4,3.6-i*.45,l,color="#e5e7eb",fontsize=9.2,fontfamily=mono,fontweight='bold' if i<2 else 'normal')
    ax.text(.4,1.75,"actual uid at write = 0",color="#fca5a5",fontsize=9.5,fontfamily=mono,fontweight='bold')
    ax.text(5.7,4.2,"$ tetragon events  (captured JSON, abridged)",color="#22c55e",fontsize=9,fontfamily=mono)
    ev=['process_exec   policy=None        binary=/var/tmp/suidpoc','               process_credentials: {uid: 1000, euid: 0}','process_lsm    policy=ttb-lsm-guard binary=/var/tmp/suidpoc','               process_credentials: {uid: 1000, euid: 0}','               args: [{file_arg: {path: /proc/sys/kernel/core_pattern}}]']
    for i,l in enumerate(ev):
        ax.text(5.7,3.6-i*.42,l,color="#e5e7eb",fontsize=8.2,fontfamily=mono,fontweight='bold' if i in (1,3) else 'normal')
    ax.text(5.7,1.2,"ALERT emitted, but its uid is the exec-time snapshot (1000)",color="#fca5a5",fontsize=9.2,fontfamily=mono,fontweight='bold')
    ax.text(6.5,.7,"Evidence: experiments/results/suid-race-events-extract.jsonl (abridged)  |  PoC: testbed/poc/setuid_race.c",ha='center',fontsize=8,color="#cbd5e1")
    fig.tight_layout(); fig.savefig(OUT/'fig6_snapshot.png',dpi=300,bbox_inches='tight'); plt.close(fig)

if __name__=='__main__':
    fig1(); fig2(); fig3(); fig4(); fig5(); fig6_snapshot(); fig7_leadtime(); fig8_ablation()
    for p in sorted(OUT.glob('*.png')): print(p.name, p.stat().st_size)
