from itertools import product
from collections import Counter
import re
from .common import require,ident,number,rows
from .generalize import candidate

def parse_input(data):
    require(data,'k max_suppressed records');k=number(data['k'],2,10000);budget=number(data['max_suppressed'],0,10000)
    records=[];seen=set()
    for r in rows(data['records'],10000):
        require(r,'id age postal category');rid=ident(r['id']);number(r['age'],0,120);ident(r['category'])
        if rid in seen:raise ValueError('duplicate source row ID')
        if not isinstance(r['postal'],str) or not re.fullmatch('[0-9]{5}',r['postal']):raise ValueError('postal must be exactly five ASCII digits')
        seen.add(rid);records.append(r)
    if not records:raise ValueError('records cannot be empty')
    return k,budget,records

def analyze(data):
    k,budget,records=parse_input(data)
    candidates=[];feasible=[]
    for a,p in product(range(3),repeat=2):
        groups,suppressed,loss=candidate(records,a,p,k)
        admissible=bool(groups) and suppressed<=budget
        candidates.append({'age_level':a,'postal_level':p,'suppressed':suppressed,'ordinal_generalization_cost':str(loss),'feasible':admissible})
        if admissible:feasible.append(((loss,suppressed,a,p),groups))
    if not feasible:return {'feasible':False,'input_rows':len(records),'k':k,'candidates':candidates,'released_rows':[],'equivalence_classes':[]}
    (loss,suppressed,a,p),groups=min(feasible,key=lambda x:x[0]);released=[];classes=[]
    for (age,postal),members in sorted(groups.items()):
        counts=Counter(r['category'] for r in members)
        classes.append({'age':age,'postal':postal,'size':len(members),'distinct_categories':len(counts),
                        'category_counts':dict(sorted(counts.items()))})
        for category,count in sorted(counts.items()):
            released.extend({'age':age,'postal':postal,'category':category} for _ in range(count))
    return {'feasible':True,'input_rows':len(records),'k':k,'selected':{'age_level':a,'postal_level':p,'ordinal_generalization_cost':str(loss)},
            'suppressed_rows':suppressed,'released_count':len(released),'released_rows':released,'equivalence_classes':classes,'candidates':candidates,
            'privacy_scope':'k-anonymity applies only to the selected age/postal quasi-identifiers in this release; this is not a privacy guarantee.'}
