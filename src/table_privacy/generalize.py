from collections import defaultdict
from fractions import Fraction

def bucket(age,postal,age_level,postal_level):
    if age_level==0:a=str(age)
    elif age_level==1:a=f'{age//10*10}-{min(120,age//10*10+9)}'
    else:a='*'
    p=postal if postal_level==0 else postal[:3]+'**' if postal_level==1 else '*'
    return a,p

def candidate(records,age_level,postal_level,k):
    groups=defaultdict(list)
    for r in records:groups[bucket(r['age'],r['postal'],age_level,postal_level)].append(r)
    kept={key:group for key,group in groups.items() if len(group)>=k}
    suppressed=sum(len(g) for key,g in groups.items() if key not in kept)
    # Age and postal level are equally weighted ordinal generalization costs, not empirical information loss.
    loss=Fraction(age_level+postal_level,4)
    return kept,suppressed,loss
