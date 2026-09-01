import json
lines = open('data/curated_vulnerable_pairs.jsonl', encoding='utf-8').readlines()
seen = set()
kept = []
for l in lines:
    key = json.loads(l)['vulnerable']
    if key not in seen:
        seen.add(key)
        kept.append(l)
print(f'{len(lines)} -> {len(kept)} after dedup')
open('data/curated_vulnerable_pairs.jsonl', 'w', encoding='utf-8').writelines(kept)