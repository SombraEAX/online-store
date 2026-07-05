<template lang="pug">
	.pagination(v-if="total>1")
		nuxt-link.link.prev(v-if="prev" :to="prev") ←
		nuxt-link.link(v-for="link in links" :to="link.url" :class="{active:link.active}") {{link.caption}}
		nuxt-link.link.next(v-if="next" :to="next") →
</template>
<style scoped lang="scss">
.pagination{
	display:flex
}
.pagination .link{
	color:#000;
	display:block;
	width:40px;
	height:40px;
	border-radius:50%;
	text-decoration:none;
	text-align:center;
	font-size:16px;
	padding-top:12px;
	box-sizing:border-box;
	line-height:16px;
	margin:5px
}
.pagination .active,.pagination .link:hover{
	background:#ddd
}
.pagination .active{
	cursor:default
}
</style>
<script>
	export default {
		props:['total','current','url'],
		computed:{
			next(){
				let current = Number(this.current)
				let total   = Number(this.total)
				return current < total && (this.url + (current + 1))
			},
			prev(){
				let current = Number(this.current)
				return current > 1 && (this.url + (current - 1))
			},
			links(){
				let current = Number(this.current)
				let total   = Number(this.total)
				
				let links = []
				let start = Math.max(current - 2, 1)
				let stop  = Math.min(current + 2, total)

				if(stop-start < 4){
					if(current < 3){
						stop = Math.min(start+4, total)
					}else{
						start = Math.max(stop-4, 1)
					}
				}

				for(let i = start; i <= stop; i++){
					links.push({url:this.url + i, caption: i, active: current === i})
				}

				return links
			}
		}
	}
</script>
