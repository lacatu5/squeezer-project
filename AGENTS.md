# Squeezer Scanner Architecture

Strict rules:
- Do not use any comment in the code
- Do not use any docstring, if you see any remove them !!!
- Do not accumulate garbage, remove unused functions, code snippets
- Use async/await for all I/O operations
- If you modify this file to add more things, don't make it too complex (i mean, more than needed)
- If there are some values that are in python files but they should be in JSON files, do it
- "El token de autenticación se obtiene manualmente mediante login en la aplicación, y se proporciona al escáner mediante el parámetro --bearer o archivo de configuración. Este enfoque evita la complejidad de automatizar el flujo de login en SPAs modernas donde la autenticación es asíncrona (XHR/Fetch).
- Remember this is a general purpose web scanner, so you shouldnt put hardcacoded stuff or app specific stuff in the code