# TODO: the experiment name should be automatically inferred from the file name + function_name.
# TODO: after writing this experiment, do some refactoring in the experiments code.
# TODO: object oriented experiments to not duplicate data.

# TODO: create the experiment with the following parts: (each in a separate figure).
# TODO: single cube with increasing number of dimensions, with increasing cube complexity.
# TODO: linear #cubes without interference between cubes
# TODO: linear #cubes with interference between cubes
# TODO: quadratic #cubes without interference between cubes
# TODO: quadratic #cubes with interference between cubes
# TODO: IDEA: I can actually get positive examples by drawing from the set, and negative samples using
#   randomization.
# TODO: consider creating a class for running an experiment. might be useful.
from abc import abstractmethod

from CanonicalHyperCubeSet import CanonicalHyperCubeSet
from DimensionsManager import DimensionsManager
from MinDFA import MinDFA
from smt_experiments.experiments.experiment_utils import EngineType, Variable, get_y_var_list, \
    get_positive_membership_operation, get_negative_membership_operation
from smt_experiments.experiments.n_unions_string_experiment import BasicSet, get_string_list
from smt_experiments.experiments.plot_experiment_results import plot_results
from smt_experiments.experiments.run_experiment import run_experiment
from smt_experiments.z3_sets.z3_product_set import Z3ProductSet
from smt_experiments.z3_sets.z3_string_set import Z3StringSet


def _get_contained_element(n_dims: int, basic_set: BasicSet) -> list[str]:
    s = get_string_list(1)[0]
    element = [s for _ in range(n_dims)]
    if basic_set == BasicSet.PREFIX:
        element = [entry + 'xxx' for entry in element]
    if basic_set == BasicSet.SUFFIX:
        element = ['xxx' + entry for entry in element]
    return element


def get_classes(engine):
    if engine == EngineType.Z3:
        single_dim_set_cls = Z3StringSet
        product_set_cls = Z3ProductSet
    else:  # engine == EngineType.OUR:
        single_dim_set_cls = MinDFA
        product_set_cls = CanonicalHyperCubeSet
    return product_set_cls, single_dim_set_cls


def mutate_string(s: str, basic_set: BasicSet, is_in: bool) -> str:
    if not is_in:
        s = s[:-1] + '@'
    if basic_set == BasicSet.PREFIX:
        s = s + 'xxx'
    if basic_set == BasicSet.SUFFIX:
        s = 'xxx' + s
    return s


class MultipleStringDimensionsExperiment:
    @property
    @abstractmethod
    def experiment_name(self) -> str:
        pass

    @property
    @abstractmethod
    def min_dims(self) -> int:
        pass

    @property
    @abstractmethod
    def max_dims(self) -> int:
        pass

    @property
    @abstractmethod
    def step(self) -> int:
        pass

    def dim_names(self, n_dims: int = None) -> list[str]:
        if n_dims is None:
            n_dims = self.max_dims
        return [str(i) for i in range(n_dims)]

    @abstractmethod
    def get_contained_elements(self, engine: EngineType, n_dims: int, basic_set: BasicSet) -> list[list[str]]:
        pass

    @abstractmethod
    def get_not_contained_elements(self, engine: EngineType, n_dims: int, basic_set: BasicSet) -> list[list[str]]:
        pass

    @abstractmethod
    def get_set(self, engine: EngineType, n_dims: int, basic_set: BasicSet):
        pass

    def run(self):
        operation_list = [
            get_positive_membership_operation(self.get_contained_elements),
            get_negative_membership_operation(self.get_not_contained_elements)
        ]
        set_params_options = {
            'engine': list(EngineType),
            'n_dims': list(range(self.min_dims, self.max_dims + 1, self.step)),
            'basic_set': list(BasicSet)
        }

        dim_manager = DimensionsManager()
        for dim_name in self.dim_names():
            dim_manager.set_domain(dim_name, dim_manager.DimensionType.DFA)

        run_experiment(
            experiment_name=self.experiment_name,
            set_params_options=set_params_options,
            get_set_from_params=self.get_set,
            operation_list=operation_list,
        )

    def plot(self):
        x_var = Variable(
            'n_dims',
            lambda result: result['set_params']['n_dims']
        )

        horizontal_var_list = [
            Variable(
                'basic_set',
                lambda result: result['set_params']['basic_set']
            )
        ]

        legend_var_list = [
            Variable(
                'engine',
                lambda result: result['set_params']['engine']
            )
        ]
        plot_results(
            experiment_name=self.experiment_name,
            x_var=x_var,
            y_var_list=get_y_var_list(),
            horizontal_var_list=horizontal_var_list,
            legend_var_list=legend_var_list,
        )


def string_to_wildcard(basic_set, s):
    if basic_set == BasicSet.SUFFIX:
        s = '*' + s
    if basic_set == BasicSet.PREFIX:
        s = s + '*'
    return s


class SingleSimpleCube(MultipleStringDimensionsExperiment):
    experiment_name = 'multiple_string_dimensions_single_simple_cube'
    min_dims = 1
    max_dims = 10
    step = 1

    def get_contained_elements(self, engine: EngineType, n_dims: int, basic_set: BasicSet) -> list[list[str]]:
        return [_get_contained_element(n_dims, basic_set)]

    def get_not_contained_elements(self, engine: EngineType, n_dims: int, basic_set: BasicSet) -> list[list[str]]:
        elements = self.get_contained_elements(engine, n_dims, basic_set)
        new_elements = []
        for element in elements:
            new_element = []
            for entry in element:
                i = 4
                new_entry = entry[:i - 1] + '@' + entry[i:]
                new_element.append(new_entry)
            new_elements.append(new_element)
        return new_elements

    def get_set(self, engine: EngineType, n_dims: int, basic_set: BasicSet):
        product_set_cls, single_dim_set_cls = get_classes(engine)

        s = get_string_list(1)[0]
        s = string_to_wildcard(basic_set, s)

        dim_names = self.dim_names(n_dims)
        cube = [single_dim_set_cls.from_wildcard(s) for _ in range(n_dims)]
        representation = f'{s} ^ {n_dims}'

        return product_set_cls.create_from_cube(dim_names, cube, dim_names), representation


class LinearNumberOfNonIntersectingCubes(MultipleStringDimensionsExperiment):
    experiment_name = 'multiple_string_dimensions_linear_number_of_non_intersecting_cubes'
    min_dims = 1
    max_dims = 20
    step = 1

    def _get_elements(self, n_dims: int, basic_set: BasicSet, contained: bool) -> list[list[str]]:
        string_list = get_string_list(n_dims)
        elements = []
        for s in string_list:
            s = mutate_string(s, basic_set, contained)
            element = [s for _ in range(n_dims)]
            elements.append(element)
        return elements

    def get_contained_elements(self, engine: EngineType, n_dims: int, basic_set: BasicSet) -> list[list[str]]:
        return self._get_elements(n_dims, basic_set, True)

    def get_not_contained_elements(self, engine: EngineType, n_dims: int, basic_set: BasicSet) -> list[list[str]]:
        return self._get_elements(n_dims, basic_set, False)

    def get_set(self, engine: EngineType, n_dims: int, basic_set: BasicSet):
        product_set_cls, single_dim_set_cls = get_classes(engine)
        string_list = get_string_list(n_dims)

        product_set = product_set_cls(self.dim_names(n_dims))
        representation_list = []
        for s in string_list:
            s = string_to_wildcard(basic_set, s)
            cube = [single_dim_set_cls.from_wildcard(s) for _ in range(n_dims)]
            product_set.add_cube(cube)
            representation_list.append('{' + s + '} ^ ' + str(n_dims))

        representation = '|'.join(representation_list)
        return product_set, representation


if __name__ == '__main__':
    # experiment = SingleSimpleCube()
    experiment = LinearNumberOfNonIntersectingCubes()
    experiment.run()
    experiment.plot()

