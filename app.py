from flask import Flask, jsonify, render_template, request
import joblib, pandas as pd, numpy as np, os, re
from datetime import datetime
from sklearn.metrics import accuracy_score, f1_score

app = Flask(__name__)

<<<<<<< HEAD
MODELS_DIR = 'models'

DEFAULT_SEVERITY = {
    'Benign': 'SAFE',
    'UDP_Flood': 'HIGH',
    'TCP_Flood': 'HIGH',
    'SYN_Flood': 'CRITICAL',
    'HTTP_Flood': 'HIGH',
    'ICMP_Flood': 'MEDIUM',
    'UDP Flood': 'HIGH',
    'TCP-SYN Flood': 'CRITICAL',
    'HTTP Flood': 'HIGH',
    'ICMP Flood': 'MEDIUM',
    'Slowloris Flood': 'HIGH',
    'DNS Amplification': 'CRITICAL',
    'ACK Flood': 'HIGH',
    'Volumetric Flood': 'CRITICAL'
}

=======
CLASS_NAMES = {
    0: 'Benign', 1: 'Botnet/Bashlite', 2: 'Backdoor/HttpBackdoor',
    3: 'Backdoor/Generic', 4: 'Backdoor/TheTick', 5: 'Ransomware-PoC',
    6: 'Coinminer/XMRig', 7: 'Rootkit/Beurk', 8: 'Rootkit/Bdvl'
}
SEVERITY = {
    0: 'SAFE', 1: 'HIGH', 2: 'HIGH', 3: 'HIGH', 4: 'HIGH',
    5: 'CRITICAL', 6: 'MEDIUM', 7: 'CRITICAL', 8: 'CRITICAL'
}
>>>>>>> f377f9accf5ff89455bc1f68cae96561b11be34d
DEVICE_POOL = [
    'RPi-MedSensor-01', 'RPi-HeartRate-02', 'RPi-BloodPressure-03',
    'RPi-Glucose-04', 'IP-Camera-ICU-01', 'IP-Camera-Ward-02',
    'SmartPump-01', 'SmartPump-02', 'Infusion-Controller-01',
    'Infusion-Controller-02', 'VentMonitor-01', 'VentMonitor-02',
    'Gateway-Floor1', 'Gateway-Floor2', 'ECG-Monitor-01', 'ECG-Monitor-02',
    'Thermostat-A1', 'OxygenSensor-01', 'BP-Cuff-Smart-01', 'Bed-Sensor-03'
]

<<<<<<< HEAD
loaded_models = {}
X_test_data = None
y_test_data = None
sorted_unique_labels = []
int_to_str_map = {}
str_to_int_map = {}

def get_severity(class_name):
    """Determine threat severity level for a class."""
    if not class_name:
        return 'SAFE'
    c_str = str(class_name)
    if 'benign' in c_str.lower() or 'normal' in c_str.lower():
        return 'SAFE'
    if c_str in DEFAULT_SEVERITY:
        return DEFAULT_SEVERITY[c_str]
    for k, v in DEFAULT_SEVERITY.items():
        if k.lower() in c_str.lower():
            return v
    return 'CRITICAL' if 'syn' in c_str.lower() or 'amplification' in c_str.lower() else 'HIGH'

def get_available_models():
    """Automatically discover all .pkl model files in the models/ folder."""
    discovered = {}
    if os.path.exists(MODELS_DIR):
        for fname in sorted(os.listdir(MODELS_DIR)):
            if fname.lower().endswith('.pkl'):
                full_path = os.path.join(MODELS_DIR, fname)
                base = os.path.splitext(fname)[0]
                
                # Format friendly display title
                clean_title = base.replace('_', ' ').replace('-', ' ').title()
                if clean_title.lower().endswith(' model'):
                    clean_title = clean_title[:-6]
                
                discovered[fname] = {
                    'key': fname,
                    'filename': fname,
                    'display_name': f"{clean_title} ({fname})",
                    'path': full_path
                }
    return discovered

def find_model_path(key):
    """Find path for a model key, filename, or alias."""
    if not key:
        return None

    # Direct filename match in models/
    candidate = os.path.join(MODELS_DIR, key)
    if os.path.exists(candidate):
        return candidate

    # With .pkl extension
    candidate_pkl = os.path.join(MODELS_DIR, f"{key}.pkl")
    if os.path.exists(candidate_pkl):
        return candidate_pkl

    # Shorthand mapping
    shorthands = {
        'rf': 'random_forest_model.pkl',
        'xgb': 'xgboost_model.pkl',
        'lgbm': 'lightgbm_model.pkl'
    }
    if key.lower() in shorthands:
        sh = os.path.join(MODELS_DIR, shorthands[key.lower()])
        if os.path.exists(sh):
            return sh

    # Fuzzy match in models directory
    if os.path.exists(MODELS_DIR):
        for fname in os.listdir(MODELS_DIR):
            if fname.lower().endswith('.pkl') and key.lower() in fname.lower():
                return os.path.join(MODELS_DIR, fname)

    return None

def get_model(key):
    """Load model from file or cache."""
    path = find_model_path(key)
    if not path or not os.path.exists(path):
        return None
    if path not in loaded_models:
        loaded_models[path] = joblib.load(path)
    return loaded_models[path]

def get_model_display_name(key):
    path = find_model_path(key)
    if path:
        fname = os.path.basename(path)
        base = os.path.splitext(fname)[0].replace('_', ' ').replace('-', ' ').title()
        if base.lower().endswith(' model'):
            base = base[:-6]
        return base
    return key.upper()

def init_data():
    global X_test_data, y_test_data, sorted_unique_labels, int_to_str_map, str_to_int_map
    if X_test_data is None and os.path.exists('data/X_test.csv'):
        X_test_data = pd.read_csv('data/X_test.csv')
    if y_test_data is None and os.path.exists('data/y_test.csv'):
        y_test_data = pd.read_csv('data/y_test.csv').squeeze()
        
        # Build dynamic class mapping based on unique classes in test data
        sorted_unique_labels = sorted(list(pd.unique(y_test_data)))
        int_to_str_map = {i: lbl for i, lbl in enumerate(sorted_unique_labels)}
        str_to_int_map = {lbl: i for i, lbl in enumerate(sorted_unique_labels)}
=======
# Tree-based models support fast SHAP TreeExplainer
TREE_MODELS = {'rf', 'xgb', 'lgbm', 'dt', 'et'}

MODELS_PATH = {
    'knn':  'models/knn_model.pkl',
    'rf':   'models/rf_model.pkl',
    'xgb':  'models/xgb_model.pkl',
    'lgbm': 'models/lgbm_model.pkl',
    'dt':   'models/dt_model.pkl',
    'et':   'models/et_model.pkl',
    'mlp':  'models/mlp_model.pkl',
    'svm':  'models/svm_model.pkl',
}

loaded_models = {}
X_test_data = None
y_test_data = None

def get_model(key):
    if key not in loaded_models:
        path = MODELS_PATH.get(key, '')
        if os.path.exists(path):
            loaded_models[key] = joblib.load(path)
    return loaded_models.get(key)

def init_data():
    global X_test_data, y_test_data
    if X_test_data is None and os.path.exists('data/X_test.csv'):
        X_test_data = pd.read_csv('data/X_test.csv')
        y_test_data = pd.read_csv('data/y_test.csv').squeeze()
>>>>>>> f377f9accf5ff89455bc1f68cae96561b11be34d

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    init_data()
<<<<<<< HEAD
    models = get_available_models()
    return jsonify({
        'data_loaded': X_test_data is not None,
        'data_samples': len(X_test_data) if X_test_data is not None else 0,
        'models': list(models.values()),
        'models_count': len(models)
=======
    return jsonify({
        'data_loaded': X_test_data is not None,
        'data_samples': len(X_test_data) if X_test_data is not None else 0,
        'models_available': {k: os.path.exists(v) for k, v in MODELS_PATH.items()},
>>>>>>> f377f9accf5ff89455bc1f68cae96561b11be34d
    })

@app.route('/api/run', methods=['POST'])
def api_run():
    init_data()
<<<<<<< HEAD
    if X_test_data is None or y_test_data is None:
        return jsonify({'error': 'Test data not found. Export X_test.csv and y_test.csv to the data/ folder.'}), 400

    body = request.json or {}
    model_key = body.get('model', '')
    
    # If no model key passed, pick first available .pkl model
    if not model_key:
        available = get_available_models()
        if available:
            model_key = list(available.keys())[0]

    model = get_model(model_key)
    if model is None:
        return jsonify({'error': f'Model "{model_key}" could not be loaded from models/ folder. Ensure a .pkl model is present.'}), 400

    n_samples = min(int(body.get('samples', 450)), len(X_test_data))

    # Dynamic stratified sampling across unique classes
    unique_classes = pd.unique(y_test_data)
    num_classes = max(1, len(unique_classes))
    per_class = max(1, n_samples // num_classes)
    
    idx = []
    for c in unique_classes:
        ci = y_test_data[y_test_data == c].index.tolist()
        if ci:
            idx.extend(np.random.choice(ci, min(per_class, len(ci)), replace=False).tolist())

    if not idx:
        idx = list(range(min(n_samples, len(X_test_data))))
    elif len(idx) < n_samples:
        remainder = n_samples - len(idx)
        selected_set = set(idx)
        remaining_pool = [i for i in range(len(X_test_data)) if i not in selected_set]
        if remaining_pool:
            idx.extend(np.random.choice(remaining_pool, min(remainder, len(remaining_pool)), replace=False).tolist())
=======
    if X_test_data is None:
        return jsonify({'error': 'Test data not found. Export X_test.csv and y_test.csv to the data/ folder.'}), 400

    body = request.json or {}
    model_key = body.get('model', 'knn')
    n_samples = min(int(body.get('samples', 500)), len(X_test_data))

    model = get_model(model_key)
    if model is None:
        return jsonify({'error': f'Model "{model_key}" not found in models/ folder.'}), 400

    # Stratified sample — equal from each class
    per_class = max(1, n_samples // 9)
    idx = []
    for c in range(9):
        ci = y_test_data[y_test_data == c].index.tolist()
        idx.extend(np.random.choice(ci, min(per_class, len(ci)), replace=False).tolist())
>>>>>>> f377f9accf5ff89455bc1f68cae96561b11be34d

    X = X_test_data.loc[idx]
    y = y_test_data.loc[idx]

    Xi = X.copy()
<<<<<<< HEAD
    
    # Clean column names for LightGBM if necessary
    is_lgbm = 'lgb' in model_key.lower() or 'lightgbm' in model_key.lower() or 'lgbm' in type(model).__name__.lower()
    if is_lgbm:
        Xi.columns = [re.sub(r'[^A-Za-z0-9_]', '_', c) for c in Xi.columns]

    raw_preds = model.predict(Xi)

    # Normalize predictions if model outputs integer indices while y has string labels (or vice versa)
    if len(raw_preds) > 0 and isinstance(raw_preds[0], (int, np.integer)) and isinstance(y.iloc[0], str):
        preds = np.array([int_to_str_map.get(int(p), str(p)) for p in raw_preds])
    elif len(raw_preds) > 0 and isinstance(raw_preds[0], str) and isinstance(y.iloc[0], (int, np.integer)):
        preds = np.array([str_to_int_map.get(p, 0) for p in raw_preds])
    else:
        preds = raw_preds

    # Confidence calculation
    if hasattr(model, 'predict_proba'):
        probs = model.predict_proba(Xi)
        confs = probs.max(axis=1)
    else:
        probs = None
        confs = np.ones(len(preds))
=======
    if model_key == 'lgbm':
        Xi.columns = [re.sub(r'[^A-Za-z0-9_]', '_', c) for c in Xi.columns]

    preds = model.predict(Xi)
    probs = model.predict_proba(Xi)
    confs = probs.max(axis=1)
>>>>>>> f377f9accf5ff89455bc1f68cae96561b11be34d

    acc = accuracy_score(y, preds)
    f1  = f1_score(y, preds, average='macro')

<<<<<<< HEAD
    # Class distribution
    unique_preds = np.unique(preds)
    class_dist = {}
    for c in unique_classes:
        c_str = str(c)
        class_dist[c_str] = int((preds == c).sum())
    for p in unique_preds:
        p_str = str(p)
        if p_str not in class_dist:
            class_dist[p_str] = int((preds == p).sum())

    # Per-class accuracy
    per_class_acc = {}
    for c in unique_classes:
        mask = (y.values == c)
        c_str = str(c)
        if mask.sum() > 0:
            per_class_acc[c_str] = round(float((preds[mask] == c).mean()) * 100, 1)

    rows = []
    threats_count = 0
    benign_count = 0

    for i, (sample_idx, p, c, a) in enumerate(zip(idx, preds, confs, y.values)):
        p_name = str(p)
        a_name = str(a)
        sev = get_severity(p_name)
        
        if sev == 'SAFE':
            benign_count += 1
        else:
            threats_count += 1

        rows.append({
            'sample_idx':  int(sample_idx),
            'device':      DEVICE_POOL[i % len(DEVICE_POOL)],
            'pred':        p_name,
            'pred_name':   p_name,
            'conf':        round(float(c) * 100, 1),
            'actual':      a_name,
            'actual_name': a_name,
            'correct':     bool(p == a),
            'severity':    sev,
=======
    class_dist = {CLASS_NAMES[i]: int((preds == i).sum()) for i in range(9)}

    per_class_acc = {}
    for i in range(9):
        mask = y.values == i
        if mask.sum() > 0:
            per_class_acc[CLASS_NAMES[i]] = round(float((preds[mask] == i).mean()) * 100, 1)

    rows = []
    for i, (sample_idx, p, c, a) in enumerate(zip(idx, preds, confs, y.values)):
        rows.append({
            'sample_idx':  int(sample_idx),   # real X_test row index for SHAP
            'device':      DEVICE_POOL[i % len(DEVICE_POOL)],
            'pred':        int(p),
            'pred_name':   CLASS_NAMES[int(p)],
            'conf':        round(float(c) * 100, 1),
            'actual':      int(a),
            'actual_name': CLASS_NAMES[int(a)],
            'correct':     bool(p == a),
            'severity':    SEVERITY[int(p)],
>>>>>>> f377f9accf5ff89455bc1f68cae96561b11be34d
        })

    return jsonify({
        'accuracy':      round(acc * 100, 2),
        'macro_f1':      round(f1, 4),
<<<<<<< HEAD
        'model':         get_model_display_name(model_key),
        'model_key':     model_key,
        'total':         len(rows),
        'threats':       threats_count,
        'benign':        benign_count,
=======
        'model':         model_key.upper(),
        'model_key':     model_key,
        'total':         len(rows),
        'threats':       int((preds != 0).sum()),
        'benign':        int((preds == 0).sum()),
>>>>>>> f377f9accf5ff89455bc1f68cae96561b11be34d
        'class_dist':    class_dist,
        'per_class_acc': per_class_acc,
        'rows':          rows[:300],
    })

@app.route('/api/shap', methods=['POST'])
def api_shap():
    import shap
    init_data()
    if X_test_data is None:
        return jsonify({'error': 'Test data not loaded.'}), 400

    body = request.json or {}
<<<<<<< HEAD
    model_key = body.get('model', '')
=======
    model_key = body.get('model', 'rf')
>>>>>>> f377f9accf5ff89455bc1f68cae96561b11be34d
    sample_idx = int(body.get('sample_idx', 0))

    model = get_model(model_key)
    if model is None:
        return jsonify({'error': f'Model "{model_key}" not found.'}), 400

<<<<<<< HEAD
    sample = X_test_data.iloc[[sample_idx]].copy()
    feat_names = list(X_test_data.columns)

    is_lgbm = 'lgb' in model_key.lower() or 'lightgbm' in model_key.lower() or 'lgbm' in type(model).__name__.lower()
    if is_lgbm:
=======
    # Get single sample
    sample = X_test_data.iloc[[sample_idx]].copy()
    feat_names = list(X_test_data.columns)

    if model_key == 'lgbm':
>>>>>>> f377f9accf5ff89455bc1f68cae96561b11be34d
        sample.columns = [re.sub(r'[^A-Za-z0-9_]', '_', c) for c in sample.columns]
        feat_names_clean = list(sample.columns)
    else:
        feat_names_clean = feat_names

    try:
<<<<<<< HEAD
        # Check if model is tree-based for TreeExplainer
        cls_name = type(model).__name__.lower()
        tree_keywords = ['forest', 'xgb', 'lgb', 'tree', 'gbm', 'boost', 'extra']
        is_tree = any(k in cls_name for k in tree_keywords)

        if is_tree:
            explainer = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(sample)
        else:
            bg_idx = np.random.choice(len(X_test_data), min(50, len(X_test_data)), replace=False)
            background = X_test_data.iloc[bg_idx]
            explainer = shap.KernelExplainer(model.predict_proba, background)
            shap_values = explainer.shap_values(sample, nsamples=100)

        raw_pred = model.predict(sample)[0]
        
        # Determine human-readable predicted name
        if isinstance(raw_pred, (int, np.integer)) and int_to_str_map:
            pred_name = int_to_str_map.get(int(raw_pred), str(raw_pred))
        else:
            pred_name = str(raw_pred)

        # Determine class index for SHAP value slice
        c_idx = 0
        if hasattr(model, 'classes_'):
            classes = list(model.classes_)
            if raw_pred in classes:
                c_idx = classes.index(raw_pred)
            elif str(raw_pred) in [str(c) for c in classes]:
                c_idx = [str(c) for c in classes].index(str(raw_pred))
        elif isinstance(raw_pred, (int, np.integer)):
            c_idx = int(raw_pred)

        # Handle different SHAP output formats (multiclass list, 3D array, or 2D binary array)
        if isinstance(shap_values, list):
            if len(shap_values) == 1:
                sv = shap_values[0][0]
                base = explainer.expected_value if np.isscalar(explainer.expected_value) else explainer.expected_value[0]
            else:
                idx_to_use = min(c_idx, len(shap_values) - 1)
                sv = shap_values[idx_to_use][0]
                base = explainer.expected_value[idx_to_use] if hasattr(explainer.expected_value, '__getitem__') else explainer.expected_value
        elif isinstance(shap_values, np.ndarray):
            if shap_values.ndim == 3:
                idx_to_use = min(c_idx, shap_values.shape[2] - 1)
                sv = shap_values[0, :, idx_to_use]
                base = explainer.expected_value[idx_to_use] if hasattr(explainer.expected_value, '__getitem__') else explainer.expected_value
            elif shap_values.ndim == 2:
                sv = shap_values[0, :]
                base = explainer.expected_value if np.isscalar(explainer.expected_value) else explainer.expected_value[0]
            else:
                sv = shap_values.flatten()
                base = explainer.expected_value if np.isscalar(explainer.expected_value) else 0.0
        else:
            sv = np.zeros(sample.shape[1])
            base = 0.0

        base = float(base) if not np.isnan(base) else 0.0
=======
        if model_key in TREE_MODELS:
            # Fast TreeExplainer
            explainer = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(sample)

            # shap_values shape: (n_classes, n_samples, n_features) or (n_samples, n_features, n_classes)
            pred_class = int(model.predict(sample)[0])

            if isinstance(shap_values, list):
                sv = shap_values[pred_class][0]
                base = float(explainer.expected_value[pred_class])
            else:
                sv = shap_values[0, :, pred_class]
                base = float(explainer.expected_value[pred_class])

        else:
            # KernelExplainer for KNN/MLP/SVM — use small background
            bg_idx = np.random.choice(len(X_test_data), 50, replace=False)
            background = X_test_data.iloc[bg_idx]
            explainer = shap.KernelExplainer(model.predict_proba, background)
            shap_values = explainer.shap_values(sample, nsamples=100)
            pred_class = int(model.predict(sample)[0])

            if isinstance(shap_values, list):
                sv = shap_values[pred_class][0]
                base = float(explainer.expected_value[pred_class])
            else:
                sv = shap_values[0, :, pred_class]
                base = float(explainer.expected_value[pred_class])
>>>>>>> f377f9accf5ff89455bc1f68cae96561b11be34d

        # Build top-12 features sorted by |SHAP value|
        feat_vals = sample.iloc[0].values
        pairs = list(zip(feat_names, feat_names_clean, sv, feat_vals))
        pairs.sort(key=lambda x: abs(x[2]), reverse=True)
        top = pairs[:12]

        features = []
        for fname, _, shap_val, feat_val in top:
            features.append({
                'feature':   fname,
                'shap':      round(float(shap_val), 4),
                'value':     round(float(feat_val), 4),
                'direction': 'positive' if shap_val > 0 else 'negative',
            })

<<<<<<< HEAD
        conf = 100.0
        if hasattr(model, 'predict_proba'):
            probs = model.predict_proba(sample)[0]
            if c_idx < len(probs):
                conf = float(probs[c_idx]) * 100
            else:
                conf = float(np.max(probs)) * 100

        return jsonify({
            'pred_class':  pred_name,
            'pred_name':   pred_name,
            'confidence':  round(conf, 1),
            'base_value':  round(base, 4),
            'features':    features,
            'model':       get_model_display_name(model_key),
=======
        pred_prob = model.predict_proba(sample)[0]
        return jsonify({
            'pred_class':  pred_class,
            'pred_name':   CLASS_NAMES[pred_class],
            'confidence':  round(float(pred_prob[pred_class]) * 100, 1),
            'base_value':  round(base, 4),
            'features':    features,
            'model':       model_key.upper(),
>>>>>>> f377f9accf5ff89455bc1f68cae96561b11be34d
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    init_data()
    app.run(debug=True, port=5000)
