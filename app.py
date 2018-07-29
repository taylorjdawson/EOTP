from flask import Flask
from flask_restful import Api

# Instantiate flask server
app = Flask(__name__)
api = Api(app)

# api.add_resource(Names, '/names/<string:name>', '/names', resource_class_kwargs={'names_database': names_database})
# api.add_resource(Annotate, '/annotate',
#                  resource_class_kwargs={'names_database': names_database, 'annotator': annotator})

if __name__ == '__main__':
    app.run(threaded=True)