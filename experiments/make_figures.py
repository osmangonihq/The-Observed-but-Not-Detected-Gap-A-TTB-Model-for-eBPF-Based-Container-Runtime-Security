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
    fig, ax = plt.subplots(figsize=(13.5, 6.4))
    ax.set_xlim(0,13.5); ax.set_ylim(0,6.4); ax.axis('off')
    def box(x,y,w,h,text,fc,fs=9.5):
        ax.add_patch(patches.FancyBboxPatch((x,y),w,h,boxstyle="round,pad=0.02,rounding_size=0.08",linewidth=1.4,edgecolor="#22303f",facecolor=fc,zorder=2))
        ax.text(x+w/2,y+h/2,text,ha='center',va='center',fontsize=fs,color="#14202c",linespacing=1.35,zorder=3)
    def arrow(x1,y1,x2,y2,color="#22303f",lw=1.6):
        ax.add_patch(patches.FancyArrowPatch((x1,y1),(x2,y2),arrowstyle="-|>",mutation_scale=13,linewidth=lw,color=color,shrinkA=2,shrinkB=2,zorder=1))
    y=4.25
    box(0.25,y,2.75,1.35,"KERNEL EVENT\nescape syscall / LSM hook\n(e.g. write to release_agent)","#dbeafe")
    box(3.55,y,2.75,1.35,"OBSERVATION  O(e)\neBPF kprobe / tracepoint / LSM\n'complete visibility'","#dcfce7")
    box(6.85,y,2.75,1.35,"POLICY DECISION  P(e)\ncondition over event fields\n+ metadata + telemetry state","#fef9c3")
    box(10.35,4.85,2.5,0.8,"ALERT   D(e)=1","#bbf7d0",fs=10.5)
    box(10.35,3.75,2.5,0.8,"NO ALERT   D(e)=0","#fecaca",fs=10.5)
    arrow(3.0,y+0.68,3.55,y+0.68); arrow(6.3,y+0.68,6.85,y+0.68)
    arrow(9.6,y+0.9,10.35,5.25); arrow(9.6,y+0.42,10.35,4.15,color="#b91c1c")
    box(0.25,1.9,2.75,1.15,"ATTACKER\nprivileged in-container\nworkload","#fee2e2")
    arrow(1.62,3.05,1.62,y)
    box(6.45,1.45,3.85,1.65,"TRUST ANCHORS (delegated inputs)\nTB-01 privilege flags    TB-02 allowlists\nTB-03 telemetry gaps   TB-04 binary names\nTB-05 no LSM cross-check   TB-06 snapshots","#ffe4e6",fs=9)
    arrow(8.37,3.1,8.37,y)
    ax.text(6.55,0.55,"OBSERVED-BUT-NOT-DETECTED GAP:  O(e)=1 but P(e)=0 because P trusts an anchor the attacker can invalidate",ha='center',fontsize=9.4,fontweight='bold',color="#991b1b")
    fig.tight_layout(); fig.savefig(OUT/'fig1_dtb_model.png',dpi=300,bbox_inches='tight'); plt.close(fig)

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

def fig7_ablation():
    th=ABL["thresholds"]; fig,ax=plt.subplots(figsize=(8.5,4.5))
    for t,color in zip(tools,["#1f77b4","#ff7f0e","#2ca02c"]):
        vals=[ABL["tools"][t][str(x)]["gap_ratio"] for x in th]
        ax.plot(th,vals,marker='o',label=t,color=color,linewidth=2)
    ax.set_xlabel("TDS robustness threshold",fontsize=10); ax.set_ylabel("Gap ratio",fontsize=10); ax.set_ylim(0,1)
    ax.legend(fontsize=10); ax.grid(alpha=.3); fig.tight_layout()
    fig.savefig(OUT/'fig7_ablation.png',dpi=300,bbox_inches='tight'); plt.close(fig)

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
    fig1(); fig2(); fig3(); fig4(); fig5(); fig6_snapshot(); fig7_ablation()
    for p in sorted(OUT.glob('*.png')): print(p.name, p.stat().st_size)
