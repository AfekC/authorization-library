import json, os, math

TMP = r"C:\Users\afek8\Downloads\auth-library\.understand-anything\tmp"
OUT = r"C:\Users\afek8\Downloads\auth-library\.understand-anything\intermediate"

def complexity_for(file_node):
    lines = file_node.get("sizeLines", 0)
    if lines > 100:
        return "complex"
    if lines > 30:
        return "moderate"
    return "simple"

def summary_for(path, structure, fc):
    name = os.path.basename(path)
    if ".spec." in name or "Test" in name:
        return f"Tests for {path.split('/')[-2] if '/' in path else path}"
    if fc == "docs":
        return f"Documentation: {name}"
    if fc == "config":
        return f"Configuration: {name}"
    if fc == "infra":
        if "Dockerfile" in name:
            return f"Docker container definition for {path.split('/')[1] if '/' in path else ''}"
        return f"Infrastructure: {name}"
    if fc == "script":
        return f"Build script: {name}"
    classes = structure.get("classes", [])
    funcs = structure.get("functions", [])
    s = ""
    if classes:
        s = f"Defines {', '.join(c['name'] for c in classes[:3])}"
    elif funcs:
        s = f"Provides {', '.join(f['name'] for f in funcs[:3])}"
    else:
        s = f"Module {name}"
    return s

def tags_for(file_node, structure):
    t = []
    lang = file_node.get("language", "")
    if lang: t.append(lang)
    fc = file_node.get("fileCategory", "")
    if fc: t.append(fc)
    name = os.path.basename(file_node["path"])
    if ".spec." in name or "Test" in name:
        t.append("test")
    if structure.get("classes"):
        t.append("class-def")
    if structure.get("functions"):
        t.append("function-def")
    if fc == "docs":
        t.append("documentation")
    if fc == "config":
        t.append("configuration")
    if fc == "infra":
        if "Dockerfile" in name:
            t.append("docker")
        else:
            t.append("infrastructure")
    if fc == "script":
        t.append("script")
    return t

def file_node_type(fc):
    return {"code": "file", "config": "config", "docs": "document",
            "infra": "service", "data": "schema", "script": "file", "markup": "file"}.get(fc, "file")

def process_all():
    total_nodes = 0
    total_edges = 0

    for bi in range(1, 6):
        with open(os.path.join(TMP, f"batch-input-{bi}.json"), "r", encoding="utf-8") as f:
            data = json.load(f)

        file_nodes = []
        func_class_nodes = []
        edges = []
        file_node_map = {}

        for file_ in data["files"]:
            path = file_["path"].replace("\\", "/")
            struct = file_["structure"]
            fc = file_.get("fileCategory", "code")
            ntype = file_node_type(fc)

            # Determine node type
            fnode = {
                "id": f"file:{path}",
                "type": ntype,
                "name": os.path.basename(path),
                "filePath": path,
                "summary": summary_for(file_["path"], struct, fc),
                "tags": tags_for(file_, struct),
                "complexity": complexity_for(file_)
            }
            file_nodes.append(fnode)
            file_node_map[path] = fnode

            # Function nodes (exported, or 10+ lines)
            for func in struct.get("functions", []):
                name = func["name"]
                f_len = func.get("endLine", 0) - func.get("startLine", 0) + 1
                is_exported = any(e["name"] == name and e.get("line") and e["line"] >= func.get("startLine", 0) - 1 and e["line"] <= func.get("endLine", 0) + 1 for e in struct.get("exports", []))
                if is_exported or f_len >= 10:
                    fid = f"function:{path}:{name}"
                    func_class_nodes.append({
                        "id": fid,
                        "type": "function",
                        "name": name,
                        "filePath": path,
                        "summary": f"Function {name} in {os.path.basename(path)}",
                        "tags": ["function"] + (["exported"] if is_exported else []),
                        "complexity": "complex" if f_len > 50 else ("moderate" if f_len > 20 else "simple")
                    })
                    edges.append({
                        "source": f"file:{path}", "target": fid,
                        "type": "contains", "direction": "forward", "weight": 1.0
                    })
                    if is_exported:
                        edges.append({
                            "source": f"file:{path}", "target": fid,
                            "type": "exports", "direction": "forward", "weight": 0.8
                        })

            # Class nodes (exported, or 20+ lines, or 2+ methods)
            for cls in struct.get("classes", []):
                name = cls["name"]
                cls_len = cls.get("endLine", 0) - cls.get("startLine", 0) + 1
                n_methods = len(cls.get("methods", []))
                is_exported = any(e["name"] == name for e in struct.get("exports", []))
                if is_exported or cls_len >= 20 or n_methods >= 2:
                    cid = f"class:{path}:{name}"
                    func_class_nodes.append({
                        "id": cid,
                        "type": "class",
                        "name": name,
                        "filePath": path,
                        "summary": f"Class {name} in {os.path.basename(path)}",
                        "tags": ["class"] + (["exported"] if is_exported else []),
                        "complexity": "complex" if cls_len > 80 else ("moderate" if cls_len > 30 else "simple")
                    })
                    edges.append({
                        "source": f"file:{path}", "target": cid,
                        "type": "contains", "direction": "forward", "weight": 1.0
                    })
                    if is_exported:
                        edges.append({
                            "source": f"file:{path}", "target": cid,
                            "type": "exports", "direction": "forward", "weight": 0.8
                        })

            # Import edges
            for imp in file_.get("importData", []):
                imp_path = imp.replace("\\", "/")
                target_id = f"file:{imp_path}"
                edges.append({
                    "source": f"file:{path}",
                    "target": target_id,
                    "type": "imports",
                    "direction": "forward",
                    "weight": 0.7
                })

            # Test edges (if file is a test, link to production files it imports)
            name = os.path.basename(path)
            is_test = ".spec." in name or "Test." in name
            if is_test:
                for imp in file_.get("importData", []):
                    imp_path = imp.replace("\\", "/")
                    if "/src/" in imp_path or "/main/" in imp_path:
                        edges.append({
                            "source": f"file:{path}",
                            "target": f"file:{imp_path}",
                            "type": "tested_by",
                            "direction": "forward",
                            "weight": 0.5
                        })

            # Cross-file calls from callGraph (function-to-function)
            for call in struct.get("callGraph", []):
                caller = call.get("caller", "")
                callee = call.get("callee", "")
                if not caller or not callee:
                    continue
                caller_id = f"function:{path}:{caller}"
                # We can emit calls edges only when both sides are known nodes
                # For simplicity, check if caller is a known function node

        # Collect all nodes
        all_nodes = file_nodes + func_class_nodes

        output = {"nodes": all_nodes, "edges": edges}
        with open(os.path.join(OUT, f"batch-{bi}.json"), "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)

        total_nodes += len(all_nodes)
        total_edges += len(edges)

        print(f"Batch {bi}: {len(all_nodes)} nodes, {len(edges)} edges")

    print(f"\nBatches 1-5 complete. Total nodes: {total_nodes}, Total edges: {total_edges}")

if __name__ == "__main__":
    process_all()
