from flask import Flask, render_template, abort
import requests
from os import urandom

# Constants
PORT = 5457

# Object inits
app = Flask(__name__)


# Funcs
def get_artifacts(ID):
    pipelines = requests.get(f'https://gitlab.com/api/v4/projects/{ID}/pipelines').json()
    if not pipelines or type(pipelines) is dict:
        return False
    web_url = requests.get(f'https://gitlab.com/api/v4/projects/{ID}').json()['web_url']
    latest_pipeline = pipelines[0]['id']
    jobs = requests.get(f'https://gitlab.com/api/v4/projects/{ID}/pipelines/{latest_pipeline}/jobs').json()
    urls = []
    for job in jobs:
        artifact_file_type = job['artifacts'][1]['file_type']
        if artifact_file_type in ('sast', 'secret_detection'):
            urls.append(f'{web_url}/-/jobs/{job["id"]}/artifacts/download?file_type={artifact_file_type}')
    return [requests.get(url).json() for url in urls]


def find_all_vulnerabilities(artifacts):
    out = []
    for artifact in artifacts:
        for item in artifact['vulnerabilities']:
            out.append({
                'severity': item['severity'],
                'message': item['message'],
                'location': item['location'],  # dict
                'url': item['identifiers'][0]['url'],
            })
    return out


def get_name(ID):
    return requests.get(f'https://gitlab.com/api/v4/projects/{ID}').json()['name']


# Routes
@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/view/<path:name>')
def view_sast(name):
    name = name.replace('/', '%2F')
    print(f'https://gitlab.com/api/v4/projects/{name}')
    try:
        ID = requests.get(f'https://gitlab.com/api/v4/projects/{name}').json()['id']
    except KeyError:
        abort(404)
    artifacts = get_artifacts(ID)
    if not artifacts:
        return "Project doesn't exist or has no security reports configured."
    return render_template('report.html', vulnerabilities=find_all_vulnerabilities(artifacts), name=get_name(ID))


# Run
if __name__ == '__main__':
    app.secret_key = urandom(15)
    app.run(host='0.0.0.0', port=PORT, debug=False)
