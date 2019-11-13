def flatten_tags(l):
    r = {}
    for e in l:
        if not e.get('key') or not e.get('value'):
            raise RuntimeError('Missing key or value for tag!')
        r[e['key']] = e['value']
    return r
