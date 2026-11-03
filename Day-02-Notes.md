Wildcard IP: 0.0.0.0
yes command - tests stress on the OS

Fork Bomb
    One container is capable enough to consume resources of all other containers and the host   itself. Therefore, it is important for us to give resource limits to each container. 
        Soft Limit - ispe warning aayegi
        Hard Limit - stops
        
        This helps us deal with Fork Bomb attacks

What is Docker Resource Mapping?
`````````````````````````````````
    Docker resource mapping means restricting how much of the host’s CPU, memory, and other resources a container is allowed to use.

    Without limits, containers can consume all available host resources, impacting:

    - Other containers
    - Host OS stability
    - Production SLAs


    What Happens If You DO NOT Set Resource Limits?
    ```````````````````````````````````````````````
    Default Behavior:
    `````````````````
    - A container can use ALL host resources
    - This is the most misunderstood Docker behavior.

    Example: No Memory Limit:
    ``````````````````````````

    Docker Resource Controls:
    ```````````````````````````
    1. CPU cores Limits

    Controls how much CPU time a container can use.

    Container can use up to 2 CPU cores:
    ``````````````````````````````````````
    docker run --cpus="2" nginx

    2. Memory (RAM) Limits

    Controls maximum RAM usage.

    Option      Meaning
    --memory    Hard memory limit [ physical RAM ]

    Container cannot exceed 512 MB RAM:
    ```````````````````````````````````
    docker run --memory="512m" nginx

    3. Limit PIDS:
    docker run --pids-limit='1000' nginx



Problem with priviledged containers:
    minikube 

Never run your container as root:
    But docker image jisne banaya wo root privilege me banaya hoga, 
    we have to ensure that the image does not have any root privilege

Concept of GroupUser and AppUser - Our container must not be able to run as a root user, but only as an appuser. Every base iamge comes with root privilege, we need to rectify, limit. 

Instructor Notes
`````````````````
    Never run with --privileged. Set securityContext.privileged: false in Kubernetes YAML to deploy PODs and Container inside PODs.

    1. Attack: privileged container → full host root

    Setup (host):
    # Terminal A: simulate a "payment-service" container
    $ sudo docker run -d --name payment-service -e DB_PASSWORD='Pr0d_SBI_C0re_2026!' alpine sleep 36000

    # Terminal B: attacker's privileged container
    $ sudo docker run --privileged -it --rm --pid=host alpine sh


    Inside the attacker container:

    - find payment-service's host PID
    # ps aux | grep sleep                     

    - dump its full environment — DB_PASSWORD in plaintext
    # cat /proc/<PID>/environ   

    With --pid=host, the container shares the host's PID namespace, so /proc/<pid>/environ for any process on the box — including sibling containers - is readable.



    ==========================================================

    Never run as root.
    The default UID inside a container is 0 (root). A container breakout from root = root on the host kernel. Drop privileges with USER.

    Setup : a deliberately vulnerable "SBI Core API"

    app.py - a classic command-injection bug, the kind that shows up in real fintech code reviews:

    ------CODE-------------
    from flask import Flask, request, render_template_string
    import subprocess

    app = Flask(__name__)

    PAGE = """
    <!DOCTYPE html><html><head><title>SBI Core Diagnostics</title>
    <style>
    body{font-family:Segoe UI,sans-serif;background:#0d1b2a;color:#e0e6ed;margin:0;padding:40px;}
    .card{max-width:600px;margin:auto;background:#132a3f;padding:30px;border-radius:10px;box-shadow:0 0 20px rgba(0,0,0,.4);}
    h1{color:#4fc3f7;font-size:20px;margin-bottom:4px;}
    p.sub{color:#8aa0b4;font-size:13px;margin-top:0;}
    input{width:100%;padding:10px;margin:14px 0;border-radius:6px;border:1px solid #2a4a63;background:#0d1b2a;color:#fff;}
    button{background:#4fc3f7;color:#00263a;border:none;padding:10px 20px;border-radius:6px;font-weight:bold;cursor:pointer;}
    pre{background:#0a1520;padding:14px;border-radius:6px;white-space:pre-wrap;margin-top:16px;color:#9ce89c;}
    </style></head><body>
    <div class="card">
    <h1>&#128274; Core Banking &mdash; Network Diagnostics</h1>
    <p class="sub">Internal use only. Ping a host to verify connectivity.</p>
    <form method="get">
    <input name="host" placeholder="e.g. 10.0.4.12 or payment-gateway.internal" value="{{host}}">
    <button type="submit">Run Diagnostic</button>
    </form>
    {% if output %}<pre>{{output}}</pre>{% endif %}
    </div></body></html>
    """

    @app.route('/')
    def ping():
        host = request.args.get('host', '')
        output = ''
        if host:
            result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
            output = result.stdout + result.stderr
        return render_template_string(PAGE, host=host, output=output)

    app.run(host='0.0.0.0', port=5000)

    -----------CODE----------------



    Vulnerable Dockerfile — no USER, defaults to UID 0:
    ```````````````````````````````````````````````````````
    FROM python:3.11-slim
    RUN pip install flask && apt update && apt install -y curl iputils-ping && rm -rf /var/lib/apt/lists/*
    COPY app.py /app.py
    CMD ["python", "/app.py"]


    Attack: root RCE → full host takeover
    ``````````````````````````````````````
    $ sudo docker build -t sbi-core-api:vuln .
    $ sudo docker run -d -p 5000:5000 --name core-api sbi-core-api:vuln

    The "attacker" is just a curl request — no shell access needed yet:
    ``````
    curl "http://localhost:5000/ping?host=8.8.8.8;id"
    # uid=0(root) gid=0(root) — instant root, no privilege escalation required



    Defend: same bug, same exploit, different UID:
    ````````````````````````````````````````````````
    add two lines:

    FROM python:3.11-slim
    RUN pip install flask && apt update && apt install -y docker.io curl iputils-ping && rm -rf /var/lib/apt/lists/*
    COPY app.py /app.py
    RUN groupadd -r appuser && useradd -r -g appuser -u 1000 appuser && chown appuser:appuser /app.py
    USER appuser
    CMD ["python", "/app.py"]




    $ sudo docker build -t sbi-core-api:hardened .
    $ sudo docker run -d -p 5001:5000 --name core-api-safe sbi-core-api:hardened

    _________
    🔗 Connect with Mr. Dheeraj Madhukar :
    YouTube: https://www.youtube.com/@DheerajMadhukar
    LinkedIn -  https://www.linkedin.com/in/dheerajtechnolegends/  
    X - https://x.com/Dheerajmadhukar 
    Medium -  https://medium.com/@dheerajkmadhukar  
    GitHub - https://github.com/Dheerajmadhukar