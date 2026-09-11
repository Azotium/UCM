import gitlab

print("python-gitlab:", gitlab.__version__)

gl = gitlab.Gitlab(
    "https://gitlab.com",
    private_token="glpat-X8BYLtOBBPBkOvYFxipcxGM6MQpvOjEKdTpwN2VyNg8.01.1702ebr3g",
)

groups = gl.groups.list(get_all=True)

print("Number of groups:", len(groups))
print("Type:", type(groups[0]) if groups else None)

if groups:
    print("Name:", groups[0].name)
    print("Full path:", groups[0].full_path)
    
project = gl.projects.get("ucm-group1/ucm")

print("Project:", project.name)
print("Project ID:", project.id)
print("Web URL:", project.web_url)

print("Access level:", project.permissions)