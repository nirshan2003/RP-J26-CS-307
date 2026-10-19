from flask import Flask, jsonify, render_template, request
import joblib, pandas as pd, numpy as np, os, re
from datetime import datetime
from sklearn.metrics import accuracy_score, f1_score

app = Flask(__name__)

CLASS_NAMES = {
    0: 'Benign', 1: 'Botnet/Bashlite', 2: 'Backdoor/HttpBackdoor',
    3: 'Backdoor/Generic', 4: 'Backdoor/TheTick', 5: 'Ransomware-PoC',
    6: 'Coinminer/XMRig', 7: 'Rootkit/Beurk', 8: 'Rootkit/Bdvl'
}
SEVERITY = {
    0: 'SAFE', 1: 'HIGH', 2: 'HIGH', 3: 'HIGH', 4: 'HIGH',
    5: 'CRITICAL', 6: 'MEDIUM', 7: 'CRITICAL', 8: 'CRITICAL'
}
DEVICE_POOL = [
    'RPi-MedSensor-01', 'RPi-HeartRate-02', 'RPi-BloodPressure-03',
    'RPi-Glucose-04', 'IP-Camera-ICU-01', 'IP-Camera-Ward-02',
    'SmartPump-01', 'SmartPump-02', 'Infusion-Controller-01',
    'Infusion-Controller-02', 'VentMonitor-01', 'VentMonitor-02',
    'Gateway-Floor1', 'Gateway-Floor2', 'ECG-Monitor-01', 'ECG-Monitor-02',
    'Thermostat-A1', 'OxygenSensor-01', 'BP-Cuff-Smart-01', 'Bed-Sensor-03'
]

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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    init_data()
    return jsonify({
        'data_loaded': X_test_data is not None,
        'data_samples': len(X_test_data) if X_test_data is not None else 0,
        'models_available': {k: os.path.exists(v) for k, v in MODELS_PATH.items()},
    })

@app.route('/api/run', methods=['POST'])
def api_run():
    init_data()
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

    X = X_test_data.loc[idx]
    y = y_test_data.loc[idx]

    Xi = X.copy()
    if model_key == 'lgbm':
        Xi.columns = [re.sub(r'[^A-Za-z0-9_]', '_', c) for c in Xi.columns]

    preds = model.predict(Xi)
    probs = model.predict_proba(Xi)
    confs = probs.max(axis=1)

    acc = accuracy_score(y, preds)
    f1  = f1_score(y, preds, average='macro')

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
        })

    return jsonify({
        'accuracy':      round(acc * 100, 2),
        'macro_f1':      round(f1, 4),
        'model':         model_key.upper(),
        'model_key':     model_key,
        'total':         len(rows),
        'threats':       int((preds != 0).sum()),
        'benign':        int((preds == 0).sum()),
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
    model_key = body.get('model', 'rf')
    sample_idx = int(body.get('sample_idx', 0))

    model = get_model(model_key)
    if model is None:
        return jsonify({'error': f'Model "{model_key}" not found.'}), 400

    # Get single sample
    sample = X_test_data.iloc[[sample_idx]].copy()
    feat_names = list(X_test_data.columns)

    if model_key == 'lgbm':
        sample.columns = [re.sub(r'[^A-Za-z0-9_]', '_', c) for c in sample.columns]
        feat_names_clean = list(sample.columns)
    else:
        feat_names_clean = feat_names

    try:
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

        pred_prob = model.predict_proba(sample)[0]
        return jsonify({
            'pred_class':  pred_class,
            'pred_name':   CLASS_NAMES[pred_class],
            'confidence':  round(float(pred_prob[pred_class]) * 100, 1),
            'base_value':  round(base, 4),
            'features':    features,
            'model':       model_key.upper(),
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    init_data()
    app.run(debug=True, port=5000)
