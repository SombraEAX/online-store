<template lang="pug">
	.center-outer
		.center-inner
			slot
</template>
<style scoped lang="scss">
.center-outer{
	height:100%;
	min-height:100%;
	display:flex
}
.center-inner{
	margin:auto;
	font-size:20px
}
</style>
<script>
	export default {}
</script>
