from flask import Flask, jsonify, render_template, request
import joblib, pandas as pd, numpy as np, os, re
from datetime import datetime
from sklearn.metrics import accuracy_score, f1_score

app = Flask(__name__)

MODELS_DIR = 'models'

# Reconnaissance & Intrusion Attack Threat Severity Mapping
DEFAULT_SEVERITY = {
    'Benign': 'SAFE',
    'HostDiscovery': 'MEDIUM',
    'Host Discovery': 'MEDIUM',
    'PortScan': 'MEDIUM',
    'Port Scan': 'MEDIUM',
    'OSScan': 'HIGH',
    'OS Scan': 'HIGH',
    'VulnScan': 'HIGH',
    'Vulnerability Scan': 'HIGH',
    'BruteForce': 'CRITICAL',
    'Dictionary Brute Force': 'CRITICAL',
    'Brute Force': 'CRITICAL'
}

DEVICE_POOL = [
    'RPi-MedSensor-01', 'RPi-HeartRate-02', 'RPi-BloodPressure-03',
    'RPi-Glucose-04', 'IP-Camera-ICU-01', 'IP-Camera-Ward-02',
    'SmartPump-01', 'SmartPump-02', 'Infusion-Controller-01',
    'Infusion-Controller-02', 'VentMonitor-01', 'VentMonitor-02',
    'Gateway-Floor1', 'Gateway-Floor2', 'ECG-Monitor-01', 'ECG-Monitor-02',
    'Thermostat-A1', 'OxygenSensor-01', 'BP-Cuff-Smart-01', 'Bed-Sensor-03'
]

loaded_models = {}
loaded_metadata = {}
X_test_data = None
y_test_data = None
sorted_unique_labels = []
int_to_str_map = {}
str_to_int_map = {}

def get_severity(class_name):
    """Determine threat severity level for a class."""
    if not class_name:
        return 'SAFE'
    c_str = str(class_name).strip()
    if 'benign' in c_str.lower() or 'normal' in c_str.lower():
        return 'SAFE'
    if c_str in DEFAULT_SEVERITY:
        return DEFAULT_SEVERITY[c_str]
    for k, v in DEFAULT_SEVERITY.items():
        if k.lower() == c_str.lower() or k.lower() in c_str.lower():
            return v
    if 'brute' in c_str.lower() or 'force' in c_str.lower():
        return 'CRITICAL'
    if 'vuln' in c_str.lower() or 'exploit' in c_str.lower():
        return 'HIGH'
    if 'scan' in c_str.lower() or 'discovery' in c_str.lower():
        return 'MEDIUM'
    return 'HIGH'

def get_available_models():
    """Automatically discover all .pkl model files in the models/ folder in read-only mode."""
    discovered = {}
    name_map = {
        'rf_model.pkl': 'Random Forest (rf_model.pkl)',
        'xgb_model.pkl': 'XGBoost (xgb_model.pkl)',
        'lgb_model.pkl': 'LightGBM (lgb_model.pkl)',
        'random_forest_model.pkl': 'Random Forest (random_forest_model.pkl)',
        'xgboost_model.pkl': 'XGBoost (xgboost_model.pkl)',
        'lightgbm_model.pkl': 'LightGBM (lightgbm_model.pkl)'
    }
    if os.path.exists(MODELS_DIR):
        for fname in sorted(os.listdir(MODELS_DIR)):
            if fname.lower().endswith('.pkl'):
                full_path = os.path.join(MODELS_DIR, fname)
                base = os.path.splitext(fname)[0]
                
                if fname in name_map:
                    display_name = name_map[fname]
                else:
                    clean_title = base.replace('_', ' ').replace('-', ' ').title()
                    if clean_title.lower().endswith(' model'):
                        clean_title = clean_title[:-6]
                    display_name = f"{clean_title} ({fname})"
                
                discovered[fname] = {
                    'key': fname,
                    'filename': fname,
                    'display_name': display_name,
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
        'rf': 'rf_model.pkl',
        'xgb': 'xgb_model.pkl',
        'lgb': 'lgb_model.pkl',
        'lgbm': 'lgb_model.pkl',
        'random_forest': 'rf_model.pkl',
        'xgboost': 'xgb_model.pkl',
        'lightgbm': 'lgb_model.pkl'
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
    """Load model from file or cache (Read-only inference). Unpacks 'model' key if stored in dict."""
    path = find_model_path(key)
    if not path or not os.path.exists(path):
        return None
    if path not in loaded_models:
        # Load in read-only mode (never modify or resave)
        loaded = joblib.load(path)
        if isinstance(loaded, dict) and 'model' in loaded:
            loaded_models[path] = loaded['model']
            loaded_metadata[path] = loaded
        else:
            loaded_models[path] = loaded
            loaded_metadata[path] = {}
    return loaded_models[path]

def get_model_metadata(key):
    path = find_model_path(key)
    if path:
        if path not in loaded_metadata:
            get_model(key)
        return loaded_metadata.get(path, {})
    return {}

def get_model_display_name(key):
    path = find_model_path(key)
    if path:
        fname = os.path.basename(path)
        name_map = {
            'rf_model.pkl': 'Random Forest',
            'xgb_model.pkl': 'XGBoost',
            'lgb_model.pkl': 'LightGBM',
            'random_forest_model.pkl': 'Random Forest',
            'xgboost_model.pkl': 'XGBoost',
            'lightgbm_model.pkl': 'LightGBM'
        }
        if fname in name_map:
            return name_map[fname]
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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    init_data()
    models = get_available_models()
    return jsonify({
        'data_loaded': X_test_data is not None,
        'data_samples': len(X_test_data) if X_test_data is not None else 0,
        'models': list(models.values()),
        'models_count': len(models)
    })

@app.route('/api/run', methods=['POST'])
def api_run():
    init_data()
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

    meta = get_model_metadata(model_key)
    classes_list = None
    if 'encoder' in meta and hasattr(meta['encoder'], 'classes_'):
        classes_list = list(meta['encoder'].classes_)
    elif 'classes' in meta and meta['classes'] is not None:
        classes_list = list(meta['classes'])

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

    X = X_test_data.loc[idx]
    y = y_test_data.loc[idx]

    Xi = X.copy()
    
    # Clean column names for LightGBM if necessary
    is_lgbm = 'lgb' in model_key.lower() or 'lightgbm' in model_key.lower() or 'lgbm' in type(model).__name__.lower()
    if is_lgbm:
        Xi.columns = [re.sub(r'[^A-Za-z0-9_]', '_', c) for c in Xi.columns]

    raw_preds = model.predict(Xi)

    # Normalize predictions if model outputs integer indices while y has string labels (or vice versa)
    if len(raw_preds) > 0 and isinstance(raw_preds[0], (int, np.integer)) and isinstance(y.iloc[0], str):
        if classes_list:
            preds = np.array([classes_list[int(p)] if int(p) < len(classes_list) else str(p) for p in raw_preds])
        else:
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

    acc = accuracy_score(y, preds)
    f1  = f1_score(y, preds, average='macro')

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
        })

    return jsonify({
        'accuracy':      round(acc * 100, 2),
        'macro_f1':      round(f1, 4),
        'model':         get_model_display_name(model_key),
        'model_key':     model_key,
        'total':         len(rows),
        'threats':       threats_count,
        'benign':        benign_count,
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
    model_key = body.get('model', '')
    sample_idx = int(body.get('sample_idx', 0))

    model = get_model(model_key)
    if model is None:
        return jsonify({'error': f'Model "{model_key}" not found.'}), 400

    meta = get_model_metadata(model_key)
    classes_list = None
    if 'encoder' in meta and hasattr(meta['encoder'], 'classes_'):
        classes_list = list(meta['encoder'].classes_)
    elif 'classes' in meta and meta['classes'] is not None:
        classes_list = list(meta['classes'])

    sample = X_test_data.iloc[[sample_idx]].copy()
    feat_names = list(X_test_data.columns)

    is_lgbm = 'lgb' in model_key.lower() or 'lightgbm' in model_key.lower() or 'lgbm' in type(model).__name__.lower()
    if is_lgbm:
        sample.columns = [re.sub(r'[^A-Za-z0-9_]', '_', c) for c in sample.columns]
        feat_names_clean = list(sample.columns)
    else:
        feat_names_clean = feat_names

    try:
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
        if isinstance(raw_pred, (int, np.integer)):
            if classes_list and int(raw_pred) < len(classes_list):
                pred_name = str(classes_list[int(raw_pred)])
            elif int_to_str_map:
                pred_name = int_to_str_map.get(int(raw_pred), str(raw_pred))
            else:
                pred_name = str(raw_pred)
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
            elif pred_name in classes:
                c_idx = classes.index(pred_name)
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
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    init_data()
    app.run(debug=True, port=5000)
